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
	"log"
	"net/netip"
	"os"
	"strings"
)

var (
	Log *log.Logger
)

// Cloud names
// TODO @seankimkdy: turn these into its own type and use enums
const (
	GCP   = "gcp"
	AZURE = "azure"
)

// TODO @seankimkdy: temporary, will remove after making everything into GRPc
type CreateVpnGatewayResponse struct {
	InterfaceIps []string
	Asn          int64
}

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
func IsAddressPrivate(addressString string) (bool, error) {
	address, err := netip.ParseAddr(addressString)
	if err != nil {
		return false, err
	}
	for _, privateAddressSpace := range privateAddressSpaces {
		if privateAddressSpace.Contains(address) {
			return true, nil
		}
	}
	return false, nil
}

// Returns prefix with GitHub workflow run numbers for integration tests
func GetGitHubRunPrefix() string {
	ghRunNumber := os.Getenv("GH_RUN_NUMBER")
	if ghRunNumber != "" {
		return "github" + ghRunNumber + "-"
	}
	return ""
}
