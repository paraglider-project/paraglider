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

package orchestrator

import (
	"github.com/seancfoley/ipaddress-go/ipaddr"

	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
)

// Private ASN ranges (RFC 6996)
const (
	MIN_PRIVATE_ASN_2BYTE uint32 = 64512
	MAX_PRIVATE_ASN_2BYTE uint32 = 65534
	MIN_PRIVATE_ASN_4BYTE uint32 = 4200000000
	MAX_PRIVATE_ASN_4BYTE uint32 = 4294967294
)

// Valid messages for error codes (i.e. if the errors don't exist)
var checkMessages = map[paragliderpb.CheckCode]map[paragliderpb.CheckStatus]string{
	paragliderpb.CheckCode_Resource_Exists: {
		paragliderpb.CheckStatus_OK:    "Resource and tag exists",
		paragliderpb.CheckStatus_FAIL:  "Resource not found; Consider deleting the tag",
		paragliderpb.CheckStatus_FIXED: "Resource not found; Tag is deleted",
	},
	paragliderpb.CheckCode_Network_Exists: {
		paragliderpb.CheckStatus_OK:    "Network exists",
		paragliderpb.CheckStatus_FAIL:  "Network does not exist",
		paragliderpb.CheckStatus_FIXED: "Network is created",
	},
	paragliderpb.CheckCode_PermitListConfig: {
		paragliderpb.CheckStatus_OK:    "Permit lists are correctly configurations",
		paragliderpb.CheckStatus_FAIL:  "Permit lists are incorrectly configured",
		paragliderpb.CheckStatus_FIXED: "Permit lists are correctly configured",
	},
	paragliderpb.CheckCode_PermitListTargets:            {},
	paragliderpb.CheckCode_IntraCloudConnectionsConfigured: {},
	paragliderpb.CheckCode_MultiCloudConnectionsConfigured: {},
	paragliderpb.CheckCode_PublicConnectionsConfigured:     {},
}

func allocBlock(addressSpace *ipaddr.IPAddress, blockSize int64) *ipaddr.IPAddress {
	var allocator ipaddr.PrefixBlockAllocator[*ipaddr.IPAddress]
	allocator.AddAvailable(addressSpace)
	return allocator.AllocateSize(uint64(blockSize))
}

func removeBlock(addressSpaces []*ipaddr.IPAddress, block *ipaddr.IPAddress) []*ipaddr.IPAddress {
	var blockList []*ipaddr.IPAddress
	for _, availSpace := range addressSpaces {
		result := availSpace.Subtract(block)
		for _, addr := range result {
			blockList = append(blockList, addr.SpanWithPrefixBlocks()...)
		}
	}
	return blockList
}

func findUnusedBlocks(addressSpace []string, usedAddressSpaces []*paragliderpb.AddressSpaceMapping) []*ipaddr.IPAddress {
	availBlocks := make([]*ipaddr.IPAddress, 0)
	for _, availSpace := range addressSpace {
		availBlocks = append(availBlocks, ipaddr.NewIPAddressString(availSpace).GetAddress())
	}
	for _, usedAddress := range usedAddressSpaces {
		for _, block := range usedAddress.AddressSpaces {
			usedBlock := ipaddr.NewIPAddressString(block).GetAddress()
			availBlocks = removeBlock(availBlocks, usedBlock)
		}
	}

	return availBlocks
}

func getCheckMessages(r *paragliderpb.CheckResourceResponse) ([]string, error) {
	var messages []string
	for _, check := range []*paragliderpb.CheckResult{
		r.Resource_Exists,
		r.Network_Exists,
		r.PermitListConfig,
		r.PermitListTargets,
		r.IntraCloudConnectionsConfigured,
		r.MultiCloudConnectionsConfigured,
		r.MultiCloudConnectionsConfigured,
	} {
		if check != nil {
			messages = append(messages, getCheckMessage(check.GetCode(), check.GetStatus()))

			// Append any additional messages
			if check.Messages != nil {
				messages = append(messages, check.Messages...)
			}
		}
	}
	return messages, nil
}

func getCheckMessage(code paragliderpb.CheckCode, status paragliderpb.CheckStatus) string {
	prefix := getStatusPrefix(status)
	if msg, ok := checkMessages[code]; ok {
		if msg, ok := msg[status]; ok {
			return prefix + msg
		}
	}

	return prefix + "Could not check " + getCheckName(code)
}

func getStatusPrefix(status paragliderpb.CheckStatus) string {
	switch status {
	case paragliderpb.CheckStatus_OK:
		return "\033[92m\u2713 OK: "
	case paragliderpb.CheckStatus_FAIL:
		return "\033[91m\u2717 FAIL: "
	case paragliderpb.CheckStatus_FIXED:
		return "\033[93m\u2713 FIXED: "
	default:
		return "\033[0m\u2717 UNKNOWN: "
	}
}

func getCheckName(code paragliderpb.CheckCode) string {
	switch code {
	case paragliderpb.CheckCode_Resource_Exists:
		return "Resource Exists"
	case paragliderpb.CheckCode_Network_Exists:
		return "Network Exists"
	case paragliderpb.CheckCode_PermitListConfig:
		return "Permit List Configurations"
	case paragliderpb.CheckCode_PermitListTargets:
		return "Permit List Targets"
	case paragliderpb.CheckCode_IntraCloudConnectionsConfigured:
		return "IntraCloud Endpoints Reachability"
	case paragliderpb.CheckCode_MultiCloudConnectionsConfigured:
		return "MultiCloud Endpoints Reachability"
	case paragliderpb.CheckCode_PublicConnectionsConfigured:
		return "Public Endpoints Reachability"
	default:
		return "Other error"
	}
}
