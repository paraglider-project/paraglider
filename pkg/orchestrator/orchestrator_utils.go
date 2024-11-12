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

// Invalid messages for error codes(i.e. if the error exists)
var PgErrorMessages = map[paragliderpb.ErrorCode]string{
	paragliderpb.ErrorCode_RESOURCE_NOT_FOUND: "Resource not found; Consider deleting the tag",
	paragliderpb.ErrorCode_MISSING_RESOURCES:  "Some peering resources may be missing. Consider removing the permit lists",
}

// Valid messages for error codes (i.e. if the errors don't exist)
var PgValidMessages = map[paragliderpb.ErrorCode]string{
	paragliderpb.ErrorCode_RESOURCE_NOT_FOUND: "Resource and tag exist",
	paragliderpb.ErrorCode_MISSING_RESOURCES:  "All peering resources exist",
}

// Fixed messages for error codes (i.e. if the errors are fixed)
var PgFixedMessages = map[paragliderpb.ErrorCode]string{
	paragliderpb.ErrorCode_RESOURCE_NOT_FOUND: "Resource not found; Tag is deleted",
	paragliderpb.ErrorCode_MISSING_RESOURCES:  "Deleted connection to the missing peered resources",
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
