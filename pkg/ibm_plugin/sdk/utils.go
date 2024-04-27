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
	"strings"

	"github.com/google/uuid"

	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

// TaggedResourceType indicates the type of tagged resource to fetch
type TaggedResourceType string

const (
	VPC    TaggedResourceType = "vpc"
	SUBNET TaggedResourceType = "subnet"
	VM     TaggedResourceType = "instance"
	// Security group of a specific instance
	SG TaggedResourceType = "security-group"
	// transit gateway for vpc-peering
	GATEWAY TaggedResourceType = "gateway"

	credentialsPath = ".ibm/credentials.yaml"
	publicSSHKey    = ".ibm/keys/paraglider-key.pub"
	privateSSHKey   = ".ibm/keys/paraglider-key"

	// InvResourcePrefix is used to prefix a resource's name
	InvResourcePrefix = "paraglider"
	// InvTag is the default tag attached to all inv resources
	InvTag = "inv"
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
	return fmt.Sprintf("%v-%v-%v", InvResourcePrefix, name, uuid.New().String()[:8])
}

// IsParagliderResource returns if a given resource (e.g. permit list) belongs to paraglider
func IsParagliderResource(name string) bool {
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
	// fewer bits are left for user address space.
	return netCidr2.Contains(firstIP1) && maskSize1 >= maskSize2, nil
}
