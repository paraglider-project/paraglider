/*
Copyright 2023 The Paraglider Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ibm

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"strings"

	"github.com/google/uuid"

	k8sv1 "github.com/IBM-Cloud/container-services-go-sdk/kubernetesserviceapiv1"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/paraglider-project/paraglider/pkg/paragliderpb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

const (
	VPC     TaggedResourceType = "vpc"
	SUBNET  TaggedResourceType = "subnet"
	VM      TaggedResourceType = "instance"
	CLUSTER TaggedResourceType = "k8-cluster"
	// Security group of a specific instance
	SG TaggedResourceType = "security-group"
	// transit gateway for vpc-peering
	GATEWAY TaggedResourceType = "gateway"
	VPN     TaggedResourceType = "vpn"
	ANY     TaggedResourceType = "*"

	credentialsPath = ".ibm/credentials.yaml"
	endpointsURL    = "https://control.cloud-object-storage.cloud.ibm.com/v2/endpoints" // url containing constantly updated endpoints of regions.
	publicSSHKey    = ".ibm/keys/paraglider-key.pub"
	privateSSHKey   = ".ibm/keys/paraglider-key"
	// ParagliderResourcePrefix is used to prefix a resource's name
	ParagliderResourcePrefix = "paraglider"
	// ParagliderTag is the default tag attached to all paraglider resources
	ParagliderTag = "pg"
)

// TaggedResourceType indicates the type of tagged resource to fetch
type TaggedResourceType string

// cache of regions, initialized by GetRegions(). Shouldn't be accessed directly outside of file.
var regionCache []string

// ResourceQuery represents attributes a user can filter tagged resources by.
// Note: ResourceQuery isn't associated with resources' tags, but their attributes.
type ResourceQuery struct {
	Region string
	Zone   string
	CRN    string // cloud resource name globally identifying the resource
}

// ResourceData represents the fields retrieved from tagged resources.
type ResourceData struct {
	ID     string
	CRN    string
	Region string
	Zone   string
}

// ResourceIDInfo defines the necessary fields of a resource sent in a request
type ResourceIDInfo struct {
	ResourceGroup string `json:"resourcegroup"`
	Zone          string `json:"zone"`
	ResourceID    string `json:"resourceid"`
}

// returns url of IBM region
func endpointURL(region string) string {
	return fmt.Sprintf("https://%s.iaas.cloud.ibm.com/v1", region)
}

// CRN2ID returns ID of resource based on its CRN
func CRN2ID(crn string) string {
	index := strings.LastIndex(crn, ":")
	if index == -1 {
		utils.Log.Fatalf("CRN: %v isn't of valid format", crn)
	}
	return crn[index+1:]
}

// GenerateResourceName returns unique paraglider resource name
func GenerateResourceName(name string) string {
	return fmt.Sprintf("%v-%v-%v", ParagliderResourcePrefix, name, uuid.New().String()[:8])
}

// IsParagliderResource returns if a given resource (e.g. permit list) belongs to paraglider
func IsParagliderResource(name string) bool {
	return strings.HasPrefix(name, ParagliderResourcePrefix)
}

// DoCIDROverlap returns false if cidr blocks don't share a single ip,
// i.e. they don't overlap.
func DoCIDROverlap(cidr1, cidr2 string) (bool, error) {
	netCIDR1, err := netip.ParsePrefix(cidr1)
	if err != nil {
		return true, err
	}
	netCIDR2, err := netip.ParsePrefix(cidr2)
	if err != nil {
		return true, err
	}
	if netCIDR2.Overlaps(netCIDR1) {
		return true, nil
	}

	return false, nil
}

// IsCIDRSubset returns true if cidr1 is a subset (including equal) to cidr2
func IsCIDRSubset(cidr1, cidr2 string) (bool, error) {
	firstIP1, netCidr1, err := net.ParseCIDR(cidr1)
	// ParseCIDR() example from Docs: for CIDR="192.0.2.1/24"
	// IP=192.0.2.1 and network mask 192.0.2.0/24 are returned
	if err != nil {
		return false, err
	}

	_, netCidr2, err := net.ParseCIDR(cidr2)
	if err != nil {
		return false, err
	}
	// number of significant bits in the subnet mask
	maskSize1, _ := netCidr1.Mask.Size()
	maskSize2, _ := netCidr2.Mask.Size()
	// cidr1 is a subset of cidr2 if the first user ip of cidr1 within cidr2
	// and the network mask of cidr1 is no smaller than that of cidr2, as
	// fewer bits are left for user address space.
	return netCidr2.Contains(firstIP1) && maskSize1 >= maskSize2, nil
}

// TODO cleanup k8s clusters
func TerminateParagliderDeployments(region string) error {
	if os.Getenv("INVISINETS_TEST_PERSIST") == "1" {
		utils.Log.Printf("Skipped IBM resource cleanup function - INVISINETS_TEST_PERSIST is set to 1")
		return nil
	}
	resGroupID := GetIBMResourceGroupID()
	cloudClient, err := NewIBMCloudClient(resGroupID, region)
	if err != nil {
		return err
	}

	vpnsData, err := cloudClient.GetParagliderTaggedResources(VPN, []string{}, ResourceQuery{})
	if err != nil {
		return err
	}
	// terminate all VPNs and their associated resources.
	for _, vpnData := range vpnsData {
		// set client to the region of the current VPC
		cloudClient, err := NewIBMCloudClient(resGroupID, vpnData.Region)
		if err != nil {
			return err
		}
		err = cloudClient.DeleteVPN(vpnData.ID)
		if err != nil {
			return err
		}
	}

	vpcsData, err := cloudClient.GetParagliderTaggedResources(VPC, []string{}, ResourceQuery{})
	if err != nil {
		return err
	}
	// terminate all VPCs and their associated resources.
	for _, vpcsData := range vpcsData {
		// cloud client must be set to the region of the current VPC
		cloudClient, err := NewIBMCloudClient(resGroupID, vpcsData.Region)
		if err != nil {
			return err
		}
		err = cloudClient.TerminateVPC(vpcsData.ID)
		if err != nil {
			return err
		}
	}
	// terminate transit gateways and their connections
	transitGWs, err := cloudClient.GetParagliderTaggedResources(GATEWAY, []string{}, ResourceQuery{})
	if err != nil {
		return err
	}
	for _, gw := range transitGWs {
		err = cloudClient.DeleteTransitGW(gw.ID)
		if err != nil {
			return err
		}
	}
	return nil
}

func getClientMapKey(resGroup, region string) string {
	return resGroup + "-" + region
}

// returns ResourceIDInfo out of an agreed upon formatted string:
// "/resourcegroup/{ResourceGroupName}/zone/{zone}/resourcetype/{ResourceID}"
func getResourceMeta(deploymentID string) (ResourceIDInfo, error) {
	parts := strings.Split(deploymentID, "/")

	if parts[0] != "" || parts[1] != "resourcegroup" {
		return ResourceIDInfo{}, fmt.Errorf("invalid resource ID format: expected '/resourcegroup/{ResourceGroup}', got '%s'", deploymentID)
	}

	info := ResourceIDInfo{
		ResourceGroup: parts[2],
	}

	if len(parts) >= 4 {
		if parts[3] != "zone" {
			return ResourceIDInfo{}, fmt.Errorf("invalid resource ID format: expected '/resourcegroup/{ResourceGroup}/zone/{zone}', got '%s'", deploymentID)
		}
		info.Zone = parts[4]
	}

	return info, nil
}

func getZoneFromDesc(resourceDesc []byte) (string, error) {
	instanceOptions := vpcv1.CreateInstanceOptions{
		InstancePrototype: &vpcv1.InstancePrototypeInstanceByImage{
			Image:   &vpcv1.ImageIdentityByID{},
			Zone:    &vpcv1.ZoneIdentityByName{},
			Profile: &vpcv1.InstanceProfileIdentityByName{},
		},
	}

	clusterOptions := k8sv1.VpcCreateClusterOptions{}

	err := json.Unmarshal(resourceDesc, &clusterOptions)
	if err == nil && clusterOptions.WorkerPool != nil {
		if len(clusterOptions.WorkerPool.Zones) == 0 {
			return "", fmt.Errorf("unspecified zone definition in cluster description")
		}
		return *clusterOptions.WorkerPool.Zones[0].ID, nil
	}

	err = json.Unmarshal(resourceDesc, &instanceOptions)
	if err == nil && instanceOptions.InstancePrototype != nil {
		zone := instanceOptions.InstancePrototype.(*vpcv1.InstancePrototypeInstanceByImage).Zone
		if zone.(*vpcv1.ZoneIdentityByName).Name == nil {
			return "", fmt.Errorf("unspecified zone definition in instance description")
		}
		return *zone.(*vpcv1.ZoneIdentityByName).Name, nil
	}

	return "", fmt.Errorf("failed to unmarshal resource description:%+v", err)

}

func setRuleValToStore(ctx context.Context, client paragliderpb.ControllerClient, key, value, namespace string) error {
	setVal := &paragliderpb.SetValueRequest{
		Key:       key,
		Value:     value,
		Cloud:     utils.IBM,
		Namespace: namespace,
	}
	_, err := client.SetValue(ctx, setVal)

	return err
}

func getRuleValFromStore(ctx context.Context, client paragliderpb.ControllerClient, key, namespace string) (string, error) {
	getVal := &paragliderpb.GetValueRequest{
		Key:       key,
		Cloud:     utils.IBM,
		Namespace: namespace,
	}
	resp, err := client.GetValue(ctx, getVal)

	if err != nil {
		return "", err
	}
	return resp.Value, err
}

func delRuleValFromStore(ctx context.Context, client paragliderpb.ControllerClient, key, namespace string) error {
	delVal := &paragliderpb.DeleteValueRequest{
		Key:       key,
		Cloud:     utils.IBM,
		Namespace: namespace,
	}
	_, err := client.DeleteValue(ctx, delVal)

	return err
}

// getRegions returns regionCache. if regionCache is empty, it's initialized.
func getRegions() ([]string, error) {
	if len(regionCache) != 0 {
		return regionCache, nil
	}
	response, err := http.Get(endpointsURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	err = json.Unmarshal([]byte(responseBody), &data)
	if err != nil {
		return nil, err
	}
	for regionName := range data["service-endpoints"].(map[string]interface{})["regional"].(map[string]interface{}) {
		regionCache = append(regionCache, regionName)
	}
	return regionCache, nil
}

// DoesSliceContain returns true if a slice contains an item
func DoesSliceContain[T comparable](slice []T, target T) bool {
	for _, val := range slice {
		if val == target {
			return true
		}
	}
	return false
}

// IsRegionValid returns true if region is a valid IBM region
func IsRegionValid(region string) (bool, error) {
	regions, err := getRegions()
	if err != nil {
		return false, err
	}
	return DoesSliceContain(regions[:], region), nil
}

// returns region of string with region validation
func ZoneToRegion(zone string) (string, error) {
	lastIndex := strings.LastIndex(zone, "-")
	if lastIndex == -1 {
		// Hyphen not found, handle this situation
		return "", fmt.Errorf("Wrong format for zone: missing hyphen.")
	}
	region := zone[:lastIndex]

	if ok, err := IsRegionValid(region); ok {
		return region, err
	} else {
		return "", err
	}
}

// AreStructsEqual returns true if two given structs of the same type have matching fields values
// on all types except those listed in fieldsToExclude
func AreStructsEqual(s1, s2 interface{}, fieldsToExclude []string) bool {
	v1 := reflect.ValueOf(s1)
	v2 := reflect.ValueOf(s2)

	if v1.Type() != v2.Type() {
		return false
	}

	for i := 0; i < v1.NumField(); i++ {
		fieldName := v1.Type().Field(i).Name
		if DoesSliceContain(fieldsToExclude, fieldName) {
			continue
		}

		if !reflect.DeepEqual(v1.Field(i).Interface(), v2.Field(i).Interface()) {
			return false
		}
	}
	return true
}

// returns hash value of any struct containing primitives,
// or slices of primitives.
// fieldsToExclude contains field names to be excluded
// from hash calculation.
func GetStructHash(s interface{}, fieldsToExclude []string) (uint64, error) {
	h := fnv.New64a()
	v := reflect.ValueOf(s)
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		fieldName := v.Type().Field(i).Name
		if DoesSliceContain(fieldsToExclude, fieldName) {
			// skip fields in fieldsToExclude from hash calculation
			continue
		}
		switch f.Kind() {
		case reflect.String:
			_, err := h.Write([]byte(f.String()))
			if err != nil {
				return 0, err
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			_, err := h.Write([]byte(fmt.Sprint(f.Int())))
			if err != nil {
				return 0, err
			}
		case reflect.Bool:
			_, err := h.Write([]byte(fmt.Sprint(f.Bool())))
			if err != nil {
				return 0, err
			}
		case reflect.Slice:
			for j := 0; j < f.Len(); j++ {
				_, err := h.Write([]byte(f.Index(j).String()))
				if err != nil {
					return 0, err
				}
			}
		}
	}
	return h.Sum64(), nil
}

// GetIBMResourceGroupID returns resource group ID defined in environment variable PARAGLIDER_IBM_RESOURCE_GROUP_ID
func GetIBMResourceGroupID() string {
	resourceGroupID := os.Getenv("PARAGLIDER_IBM_RESOURCE_GROUP_ID")
	if resourceGroupID == "" {
		panic("Environment variable 'PARAGLIDER_IBM_RESOURCE_GROUP_ID' is required for testing")
	}
	return resourceGroupID
}
