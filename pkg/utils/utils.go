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
