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
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/google/uuid"

	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

// TaggedResourceType indicates the type of tagged resource to fetch
type TaggedResourceType string

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

	credentialsPath = ".ibm/credentials.yaml"
	publicSSHKey    = ".ibm/keys/paraglider-key.pub"
	privateSSHKey   = ".ibm/keys/paraglider-key"

	// ParagliderResourcePrefix is used to prefix a resource's name
	ParagliderResourcePrefix = "paraglider"
	// ParagliderTag is the default tag attached to all paraglider resources
	ParagliderTag = "pg"
)

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
func TerminateParagilderDeployments(resGroupID, region string) error {
	if os.Getenv("INVISINETS_TEST_PERSIST")== "1"{
		utils.Log.Printf("Skipped IBM resource cleanup function - INVISINETS_TEST_PERSIST is set to 1")
		return nil
	}
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
