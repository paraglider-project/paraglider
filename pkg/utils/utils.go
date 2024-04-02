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

package log

import (
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"

	"github.com/NetSys/invisinets/pkg/invisinetspb"
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
	file, err := os.Create("invisinets.log")
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	Log = log.New(file, "", log.LstdFlags|log.Lshortfile)
}

// Checks if an Invisinets permit list rule tag (either an address or address space) is contained within an address space.
func IsPermitListRuleTagInAddressSpace(permitListRuleTag, addressSpace string) (bool, error) {
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

	return prefix.Contains(addr), nil
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
func GetPermitListRulePeeringCloudInfo(permitListRule *invisinetspb.PermitListRule, usedAddressSpaceMappings []*invisinetspb.AddressSpaceMapping) ([]*PeeringCloudInfo, error) {
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
				for _, addressSpace := range usedAddressSpaceMapping.AddressSpaces {
					contained, err = IsPermitListRuleTagInAddressSpace(target, addressSpace)
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
	if MatchCloudProviders(cloud1, cloud2, AZURE, GCP) {
		return 2
	}
	return 1
}
