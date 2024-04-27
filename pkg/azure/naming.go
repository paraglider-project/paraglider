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

package azure

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const (
	invisinetsPrefix = "invisinets"
)

type ResourceIDInfo struct {
	SubscriptionID    string
	ResourceGroupName string
	ResourceName      string
}

// Extract the Vnet name from the subnet ID
func getVnetFromSubnetId(subnetId string) string {
	parts := strings.Split(subnetId, "/")
	return parts[8] // TODO @smcclure20: do this in a less brittle way
}

// getResourceIDInfo parses the resourceID to extract subscriptionID and resourceGroupName (and VM name if needed)
// and returns a ResourceIDInfo object filled with the extracted values
// a valid resourceID should be in the format of '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/...'
func getResourceIDInfo(resourceID string) (ResourceIDInfo, error) {
	parts := strings.Split(resourceID, "/")
	if len(parts) < 5 {
		return ResourceIDInfo{}, fmt.Errorf("invalid resource ID format: expected at least 5 parts in the format of '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/...', got %d", len(parts))
	}

	if parts[0] != "" || parts[1] != "subscriptions" || parts[3] != "resourceGroups" {
		return ResourceIDInfo{}, fmt.Errorf("invalid resource ID format: expected '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/...', got '%s'", resourceID)
	}

	info := ResourceIDInfo{
		SubscriptionID:    parts[2],
		ResourceGroupName: parts[4],
	}

	info.ResourceName = parts[len(parts)-1]
	return info, nil
}

// getInvisinetsResourceName returns a name for the Invisinets resource
func getInvisinetsResourceName(resourceType string) string {
	// TODO @nnomier: change based on invisinets naming convention
	return invisinetsPrefix + "-" + resourceType + "-" + uuid.New().String()
}

// getNSGRuleName returns a name for the Invisinets rule
func getNSGRuleName(ruleName string) string {
	return invisinetsPrefix + "-" + ruleName
}

func getRuleNameFromNSGRuleName(ruleName string) string {
	return strings.TrimPrefix(ruleName, invisinetsPrefix+"-")
}

func getSubnetName(resourceName string) string {
	return resourceName + "-subnet"
}

func getInvisinetsNamespacePrefix(namespace string) string {
	return invisinetsPrefix + "-" + namespace
}

// getVnetName returns the name of the invisinets vnet in the given location
// since an invisients vnet is unique per location
func getVnetName(location string, namespace string) string {
	return getInvisinetsNamespacePrefix(namespace) + "-" + location + "-vnet"
}

func getVpnGatewayVnetName(namespace string) string {
	return getVpnGatewayName(namespace) + "-vnet"
}

func getVpnGatewayName(namespace string) string {
	return getInvisinetsNamespacePrefix(namespace) + "-vpn-gw"
}

func getVPNGatewayIPAddressName(namespace string, idx int) string {
	return getVpnGatewayName(namespace) + "-ip-" + strconv.Itoa(idx)
}

func getLocalNetworkGatewayName(namespace string, cloud string, idx int) string {
	return getInvisinetsNamespacePrefix(namespace) + "-" + cloud + "-local-gw-" + strconv.Itoa(idx)
}

func getVirtualNetworkGatewayConnectionName(namespace string, cloud string, idx int) string {
	return getInvisinetsNamespacePrefix(namespace) + "-" + cloud + "-conn-" + strconv.Itoa(idx)
}
