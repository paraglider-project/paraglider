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

package gcp

import (
	"fmt"
	"strconv"
)

const (
	ikeVersion = 2
)

// TODO @seankimkdy: replace these in the future to be not hardcoded
var vpnRegion = "us-west1" // Must be var as this is changed during unit tests

func getVpnGwName(namespace string) string {
	return getParagliderNamespacePrefix(namespace) + "-vpn-gw"
}

func getRouterName(namespace string) string {
	return getParagliderNamespacePrefix(namespace) + "-router"
}

// Returns a peer gateway name when connecting to another cloud
func getPeerGwName(namespace string, cloud string) string {
	return getParagliderNamespacePrefix(namespace) + "-" + cloud + "-peer-gw"
}

// Returns a VPN tunnel name when connecting to another cloud
func getVpnTunnelName(namespace string, cloud string, tunnelIdx int) string {
	return getParagliderNamespacePrefix(namespace) + "-" + cloud + "-tunnel-" + strconv.Itoa(tunnelIdx)
}

// Returns a VPN tunnel interface name when connecting to another cloud
func getVpnTunnelInterfaceName(namespace string, cloud string, tunnelIdx int, interfaceIdx int) string {
	return getVpnTunnelName(namespace, cloud, tunnelIdx) + "-int-" + strconv.Itoa(interfaceIdx)
}

// Returns a BGP peer name
func getBgpPeerName(cloud string, peerIdx int) string {
	return cloud + "-bgp-peer-" + strconv.Itoa(peerIdx)
}

// getVpnGatewayUrl returns a fully qualified URL for a VPN Gateway
func getVpnGatewayUrl(project, region, vpnGatewayName string) string {
	return computeUrlPrefix + fmt.Sprintf("projects/%s/regions/%s/vpnGateways/%s", project, region, vpnGatewayName)
}

// getRouterUrl returns a fully qualified URL for a router
func getRouterUrl(project, region, routerName string) string {
	return computeUrlPrefix + fmt.Sprintf("projects/%s/regions/%s/routers/%s", project, region, routerName)
}

// getVpnTunnelUrl returns a fully qualified URL for a VPN Tunnel
func getVpnTunnelUrl(project, region, vpnTunnelName string) string {
	return computeUrlPrefix + fmt.Sprintf("projects/%s/regions/%s/vpnTunnels/%s", project, region, vpnTunnelName)
}

// getPeerGatewayUrl returns a fully qualified URL for a peer gateway
func getPeerGatewayUrl(project, peerGatewayName string) string {
	return computeUrlPrefix + fmt.Sprintf("projects/%s/global/externalVpnGateways/%s", project, peerGatewayName)
}
