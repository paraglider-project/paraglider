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

package utils

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/paraglider-project/paraglider/pkg/paragliderpb"
)

var (
	Log *log.Logger
)

// Cloud names
// TODO @seankimkdy: turn these into its own type and use enums
const (
	GCP   = "gcp"
	AZURE = "azure"
	IBM   = "ibm"
)

// Private address spaces as defined in RFC 1918
var privateAddressSpaces = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

func init() {
	file, err := os.Create("paraglider.log")
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	Log = log.New(file, "", log.LstdFlags|log.Lshortfile)
}

// Checks if a Paraglider permit list rule tag (either an address or address space) is contained within an address space.
func IsPermitListRuleTagInAddressSpace(permitListRuleTag string, addressSpaces []string) (bool, error) {
	for _, addressSpace := range addressSpaces {
		prefix, err := netip.ParsePrefix(addressSpace)
		if err != nil {
			return false, err
		}

		var addr netip.Addr
		if strings.Contains(permitListRuleTag, "/") {
			permitListRuleTagPrefix, err := netip.ParsePrefix(permitListRuleTag)
			if err != nil {
				return false, err
			}
			addr = permitListRuleTagPrefix.Addr()
		} else {
			addr, err = netip.ParseAddr(permitListRuleTag)
			if err != nil {
				return false, err
			}
		}
		if prefix.Contains(addr) {
			return true, nil
		}
	}

	return false, nil
}

// Checks if an IP address is public
func isIPAddressPrivate(addressString string) (bool, error) {
	var addr netip.Addr
	var err error
	if strings.Contains(addressString, "/") {
		addressPrefix, err := netip.ParsePrefix(addressString)
		if err != nil {
			return false, err
		}
		addr = addressPrefix.Addr()
	} else {
		addr, err = netip.ParseAddr(addressString)
		if err != nil {
			return false, err
		}
	}
	for _, privateAddressSpace := range privateAddressSpaces {
		if privateAddressSpace.Contains(addr) {
			return true, nil
		}
	}
	return false, nil
}

type PeeringCloudInfo struct {
	Cloud      string
	Namespace  string
	Deployment string
}

// Retrieves the peering cloud info (name, namespace, deployment) for a given permit list rule
// Notes
// 1. this method may return duplicate PeeringCloudInfos, so it's the responsibility of the cloud plugin to gracefully handle duplicates
// 2. peeringCloudInfo[i] will be nil if the target is a public IP address, so make sure to check for that
func GetPermitListRulePeeringCloudInfo(permitListRule *paragliderpb.PermitListRule, usedAddressSpaceMappings []*paragliderpb.AddressSpaceMapping) ([]*PeeringCloudInfo, error) {
	peeringCloudInfos := make([]*PeeringCloudInfo, len(permitListRule.Targets))
	for i, target := range permitListRule.Targets {
		isPrivate, err := isIPAddressPrivate(target)
		if err != nil {
			return nil, fmt.Errorf("unable to determine if address is private: %w", err)
		}
		// Public IP addresses don't require any peering setup
		if isPrivate {
			// Iterate through used address space mappings to find the cloud that the target belongs to
			contained := false
		out: // Indentation is correct and can't be fixed
			for _, usedAddressSpaceMapping := range usedAddressSpaceMappings {
				contained, err = IsPermitListRuleTagInAddressSpace(target, usedAddressSpaceMapping.AddressSpaces)
				if err != nil {
					return nil, fmt.Errorf("unable to determine if tag is in address space: %w", err)
				}
				if contained {
					peeringCloudInfos[i] = &PeeringCloudInfo{
						Cloud:      usedAddressSpaceMapping.Cloud,
						Namespace:  usedAddressSpaceMapping.Namespace,
						Deployment: *usedAddressSpaceMapping.Deployment,
					}
					break out
				}
			}
			// Return error if target does not belong to any cloud
			if !contained {
				return nil, fmt.Errorf("permit list rule target must belong to a specific cloud if it's a private address")
			}
		}
	}
	return peeringCloudInfos, nil
}

// Returns prefix with GitHub workflow run numbers for integration tests
func GetGitHubRunPrefix() string {
	ghRunNumber := os.Getenv("GH_RUN_NUMBER")
	if ghRunNumber != "" {
		return "github" + ghRunNumber + "-"
	}
	return ""
}

// Checks if cloud1 and cloud2 match with target1 and target2 in any order
func MatchCloudProviders(cloud1, cloud2, target1, target2 string) bool {
	return (cloud1 == target1 && cloud2 == target2) || (cloud1 == target2 && cloud2 == target1)
}

// Returns the number of VPN connections needed between cloud1 and cloud2
func GetNumVpnConnections(cloud1, cloud2 string) int {
	if MatchCloudProviders(cloud1, cloud2, AZURE, GCP) || MatchCloudProviders(cloud1, cloud2, AZURE, IBM) {
		return 2
	}
	return 1
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
