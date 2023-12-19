/*
Copyright 2023 The Invisinets Authors.

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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"strings"

	"github.com/google/uuid"

	utils "github.com/NetSys/invisinets/pkg/utils"
)

// TaggedResourceType indicates the type of tagged resource to fetch
type TaggedResourceType string

const (
	// VPC is virtual private cloud
	VPC TaggedResourceType = "vpc"
	// SUBNET is a IP Adress space
	SUBNET TaggedResourceType = "subnet"
	// VM is an instance/resource
	VM TaggedResourceType = "instance"
	// SG is a security group
	SG TaggedResourceType = "security-group"

	credentialsPath = ".ibm/credentials.yaml"
	publicSSHKey    = ".ibm/keys/invisinets-key.pub"
	privateSSHKey   = ".ibm/keys/invisinets-key"

	// InvResourcePrefix is used to prefix a resource's name
	InvResourcePrefix = "invisinets"
	// InvTag is the default tag attached to all inv resources
	InvTag = "inv"

	endpointsURL = "https://control.cloud-object-storage.cloud.ibm.com/v2/endpoints"
)

// ResourceQuery is used to extend query for tagged resources
type ResourceQuery struct {
	Region string
	Zone   string
}

type ResourceData struct {
	ID     string
	Region string
	Zone   string
}

// cache of regions, initialized by GetRegions().shouldn't be accessed directly.
var regionCache []string

// GetRegions returns regionCache. if regionCache is empty, it's initialized.
func GetRegions() ([]string, error) {
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
	regions, err := GetRegions()
	if err != nil {
		return false, err
	}
	return DoesSliceContain(regions[:], region), nil
}

// returns url of IBM region
func endpointURL(region string) string {
	return fmt.Sprintf("https://%s.iaas.cloud.ibm.com/v1", region)
}

// GetZonesOfRegion returns the zones of a specfied region
func GetZonesOfRegion(region string) ([]string, error) {
	zonesPerRegion := 3
	if isRegionValid, err := IsRegionValid(region); !isRegionValid || err != nil {
		return nil, fmt.Errorf("region %v isn't valid", region)
	}
	res := make([]string, zonesPerRegion)
	for i := 0; i < zonesPerRegion; i++ {
		res[i] = region + "-" + fmt.Sprint(i+1)
	}
	return res, nil
}

// CRN2ID returns ID of resource based on its CRN
func CRN2ID(crn string) string {
	index := strings.LastIndex(crn, ":")
	if index == -1 {
		utils.Log.Fatalf("CRN: %v isn't of valid format", crn)
	}
	return crn[index+1:]
}

// GenerateResourceName returns unique invisinets resource name
func GenerateResourceName(name string) string {
	return fmt.Sprintf("%v-%v-%v", InvResourcePrefix, name, uuid.New().String()[:8])
}

// IsInvisinetsResource returns if a given resource (e.g. permit list) belongs to invisinets
func IsInvisinetsResource(name string) bool {
	return strings.HasPrefix(name, InvResourcePrefix)
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
	// fewer bits is left for user address space.
	return netCidr2.Contains(firstIP1) && maskSize1 >= maskSize2, nil
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
