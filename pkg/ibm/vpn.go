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
	"strings"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

const routeType = "route"
const vpnConnectionType = "vpn-connection"

// CreateRouteBasedVPN creates a route based VPN and returns its public IPs
func (c *CloudClient) CreateRouteBasedVPN(namespace string) ([]string, error) {

	// fetch the the specified namespace's VPC in the region
	vpcData, err := c.GetParagliderTaggedResources(VPC, []string{namespace}, resourceQuery{Region: c.region})
	if err != nil {
		utils.Log.Printf("Failed to get VPC data for VPN deployment with error: %v", err)
		return nil, err
	}
	if len(vpcData) == 0 {
		return nil, fmt.Errorf("No VPC located at the region specified for VPN deployment")
	}

	subnets, err := c.GetSubnetsInVpcRegionBound(vpcData[0].ID)
	if err != nil {
		utils.Log.Printf("Failed to get subnets for VPN deployments with error: %+v", err)
		return nil, err
	}
	if len(subnets) == 0 {
		return nil, fmt.Errorf("VPC %v doesn't contain subnets. Unable to deploy VPN", vpcData[0].ID)
	}

	subnetID := *subnets[0].ID

	vpnPrototype := vpcv1.VPNGatewayPrototypeVPNGatewayRouteModePrototype{
		Name:          core.StringPtr(generateResourceName(string(VPN))),
		ResourceGroup: c.resourceGroup,
		Subnet:        &vpcv1.SubnetIdentity{ID: &subnetID},
		Mode:          core.StringPtr(vpcv1.VPNGatewayPrototypeVPNGatewayRouteModePrototypeModeRouteConst),
	}
	utils.Log.Printf("Creating VPN at %v", c.region)
	vpnInterface, _, err := c.vpcService.CreateVPNGateway(&vpcv1.CreateVPNGatewayOptions{VPNGatewayPrototype: &vpnPrototype})
	if err != nil {
		// check if a VPN was already deployed in the VPC.
		if strings.Contains(err.Error(), "quota") { // Note: relying on error string, since status code is shared with multiple errors.
			utils.Log.Printf("Route based VPN has reached its max quota of 1 VPN per VPC per region in %v.\n", c.region)
			// retrieve existing VPN
			vpn, err := c.GetVPNsInNamespaceRegion(namespace, c.region)
			if err != nil {
				utils.Log.Printf("Failed to get VPN in region %v with error: %+v", c.region, err)
				return nil, err
			}
			if len(vpn) == 0 {
				utils.Log.Printf("Failed to fetch existing VPN in region %v. Possible tagging/global search issue.", c.region)
				return nil, fmt.Errorf("Failed to fetch existing VPN in region %v", c.region)
			}
			utils.Log.Printf("Retrieving already deployed VPN gateway of VPC %v\n", vpcData[0].ID)
			ipAddresses, err := c.GetVPNIPs(vpn[0].ID) // array lookup is safe since a VPN exists
			if err != nil {
				utils.Log.Printf("Failed to get VPN IPs of VPN ID %v in region %v with error: %+v", vpn[0].ID, c.region, err)
				return nil, err
			}
			return ipAddresses, nil
		}
		utils.Log.Printf("Failed to create a VPN with Error: %+v", err)
		return nil, err
	}
	vpnData := vpnInterface.(*vpcv1.VPNGateway)
	vpnID, VPNCRN := *vpnData.ID, *vpnData.CRN

	err = c.pollVPNStatus(vpnID, true) // wait for VPN to be ready
	if err != nil {
		utils.Log.Printf("VPN polling error occurred while deploying a VPN:\n%+v", err)
		return nil, err
	}

	ipAddresses, err := c.GetVPNIPs(vpnID)
	if err != nil {
		utils.Log.Printf("Failed to get VPN IPs of newly created VPN with error:\n%+v", err)
		return nil, err
	}
	utils.Log.Printf("VPN %v was launched successfully at %v with assigned IPs: %+v", vpnID, c.region, ipAddresses)

	err = c.attachTag(&VPNCRN, []string{namespace, vpcData[0].ID})
	if err != nil {
		utils.Log.Printf("Error when attaching tags to newly created VPN id %v: %+v", vpnID, err)
		return nil, err
	}

	return ipAddresses, nil
}

// returns true if the VPN is ready/deleted within the alloted time frame.
// readyOrDeleted - if set to true polls VPN status until ready, else until deleted.
func (c *CloudClient) pollVPNStatus(vpnId string, readyOrDeleted bool) error {
	attempts := 40
	sleepDuration := 10 * time.Second
	utils.Log.Printf("\nPolling VPN status. Process might take up to %v seconds", attempts*(int(sleepDuration/time.Second)))
	for attempt := 1; attempt <= attempts; attempt += 1 {

		vpnData, _, err := c.vpcService.GetVPNGateway(c.vpcService.NewGetVPNGatewayOptions(
			vpnId,
		))

		if err != nil {
			if readyOrDeleted { // received err while waiting for ready status
				utils.Log.Printf("Error occurred while waiting for VPN %v for status update: %+v", vpnId, err)
				return err
			} else {
				return nil // VPN can't be found, since it was deleted
			}
		}

		// VPN desired status is "ready" and so is its current status
		if readyOrDeleted && *vpnData.(*vpcv1.VPNGateway).LifecycleState == vpcv1.RouteLifecycleStateStableConst {
			utils.Log.Printf("\nVPN achieved status ready in attempt No. %v\n", attempt)
			return nil
		}
		time.Sleep(sleepDuration)
	}
	return fmt.Errorf("\nVPN with ID: %v hasn't achieved desired status in the alloted time frame", vpnId)
}

// returns the public IPs of a VPN
// Note: route based VPN gateway uses the tunnel with the smaller public IP as the primary egress path if both tunnels are active.
func (c *CloudClient) GetVPNIPs(vpnId string) ([]string, error) {
	vpnData, _, err := c.vpcService.GetVPNGateway(c.vpcService.NewGetVPNGatewayOptions(
		vpnId,
	))
	if err != nil {
		utils.Log.Printf("Failed to get VPN IPs for VPN %v with error: %+v", vpnId, err)
		return nil, err
	}
	vpnMembers := vpnData.(*vpcv1.VPNGateway).Members

	publicIPs := make([]string, len(vpnMembers))
	for i, member := range vpnMembers {
		publicIPs[i] = *member.PublicIP.Address
	}

	return publicIPs, nil
}

// Creating routing table routes to VPN gateway connection.
// routes from each of the VPC's zones will redirect traffic destined to any of the specified CIDRs to the VPN tunnel.
// Idempotent function, i.e., err not raised if route already exists.
func (c *CloudClient) createRoutes(routingTableID, vpcID, VPNConnectionID string, destinationCIDRs []string) error {
	zones, err := c.GetZonesOfRegion(c.region)
	if err != nil {
		utils.Log.Printf("error while translating zones from region %v", c.region)
		return err
	}

	// create routes redirecting traffic to each destination CIDR
	for _, destinationCIDR := range destinationCIDRs {
		// TODO(cohen-j-omer) will extend to contain proper verification
		if !strings.Contains(destinationCIDR, "/") { // convert ip provided to a CIDR
			destinationCIDR += "/32"
		}

		// create a route from each zone to the specified connection
		for _, zone := range zones {
			routeConfig := &vpcv1.CreateVPCRoutingTableRouteOptions{
				VPCID:          &vpcID,
				RoutingTableID: &routingTableID,
				Destination:    &destinationCIDR,
				Zone: &vpcv1.ZoneIdentityByName{
					Name: &zone,
				},
				Action: core.StringPtr(vpcv1.CreateVPCRoutingTableRouteOptionsActionDeliverConst),
				Name:   core.StringPtr(generateResourceName(string(routeType))),
				NextHop: &vpcv1.RoutePrototypeNextHop{
					ID: &VPNConnectionID,
				},
			}

			ruleExists, priority, err := c.getAvailablePriority(routeConfig)
			if err != nil {
				utils.Log.Printf("Error occurred while getting an available rule priority to create rule %+v: %+v", routeConfig, err)
				return err
			}
			// avoid creating a duplicate rule
			if ruleExists {
				utils.Log.Printf("\nRoute with the following attributes already exists\n%+v", routeConfig)
				continue
			}

			routeConfig.Priority = &priority
			route, _, err := c.vpcService.CreateVPCRoutingTableRoute(routeConfig)
			if err != nil {
				utils.Log.Printf("Error occurred while creating a route with config %+v: %+v", routeConfig, err)
				return err
			}

			utils.Log.Printf("\nCreated route %v in zone %v", *route.ID, zone)
		}
	}
	return nil
}

// returns a connection (of the provided VPN) matching the specified peer VPN gateway IP address
func (c *CloudClient) getVPNConnectionMatchingPeerIP(VPNGatewayID, peerGWAddress string) (*vpcv1.VPNGatewayConnectionRouteModeVPNGatewayConnectionStaticRouteMode, error) {
	vpnGatewayConnections, _, err := c.vpcService.ListVPNGatewayConnections(
		&vpcv1.ListVPNGatewayConnectionsOptions{VPNGatewayID: &VPNGatewayID},
	)
	if err != nil {
		utils.Log.Printf("Error occurred while getting VPN connections matching peer VPN gateway IP address %v: %+v", peerGWAddress, err)
		return nil, err
	}
	// filter connections by
	for _, connectionInterface := range vpnGatewayConnections.Connections {
		connection := connectionInterface.(*vpcv1.VPNGatewayConnectionRouteModeVPNGatewayConnectionStaticRouteMode)
		peerConnection := connection.Peer.(*vpcv1.VPNGatewayConnectionStaticRouteModePeer)
		if *peerConnection.Address == peerGWAddress {
			return connection, nil // return matching connection
		}
	}
	// matching connection wasn't found
	return nil, nil
}

// Creates a connection on a route based VPN.
// - VPNGatewayID - ID of the VPN the connection will be created in.
// - peerGatewayIP - the remote VPN the newly created connection will connect to.
// - preSharedKey - pre-shared key for authentication between the 2 VPN connections.
// - destinationCIDR - traffic destined to this CIDR will be redirect to the newly created connection via newly created routing table routes
// - peerCloud - cloud residing the peer VPN gateway this connection is set to bridge
func (c *CloudClient) CreateVPNConnectionRouteBased(VPNGatewayID, peerGatewayIP, preSharedKey, peerCloud string, destinationCIDRs []string) error {
	var connectionID string

	if peerCloud != utils.AZURE {
		return fmt.Errorf("VPN connections are not yet supported between IBM and Peer cloud %v", peerCloud)
	}
	// get or create IKE and IPSec policies to establish a secure VPN connection
	IKEPolicyID, err := c.getOrCreateIKEPolicy(peerCloud)
	if err != nil {
		return err
	}
	IPSecPolicyID, err := c.getOrCreateIPSecPolicy(peerCloud)
	if err != nil {
		return err
	}

	// get or create a VPN connection
	connectionConfig := &vpcv1.CreateVPNGatewayConnectionOptions{
		VPNGatewayID: &VPNGatewayID,
		VPNGatewayConnectionPrototype: &vpcv1.VPNGatewayConnectionPrototypeVPNGatewayConnectionStaticRouteModePrototype{
			Peer:        &vpcv1.VPNGatewayConnectionStaticRouteModePeerPrototype{Address: &peerGatewayIP},
			Psk:         &preSharedKey,
			Name:        core.StringPtr(generateResourceName(string(vpnConnectionType))),
			IkePolicy:   &vpcv1.VPNGatewayConnectionIkePolicyPrototypeIkePolicyIdentityByID{ID: IKEPolicyID},
			IpsecPolicy: &vpcv1.VPNGatewayConnectionIPsecPolicyPrototypeIPsecPolicyIdentityByID{ID: IPSecPolicyID},
		},
	}
	connectionInterface, _, err := c.vpcService.CreateVPNGatewayConnection(connectionConfig)

	if err != nil {
		// check if connection already exists.
		if strings.Contains(err.Error(), "duplicate") { // Note: relying on error string, since status code is shared with multiple errors.
			connection, err := c.getVPNConnectionMatchingPeerIP(VPNGatewayID, peerGatewayIP)
			if err != nil {
				utils.Log.Printf("Error occurred while checking for existing connections to peer IP %v in VPN %v: %+v", peerGatewayIP, VPNGatewayID, err)
				return err
			}
			connectionID = *connection.ID
			utils.Log.Printf("\nReusing VPN connection: %v", connectionID)
		} else {
			utils.Log.Printf("Failed to create VPN connection for VPN %v to peer IP %v: %+v", peerGatewayIP, VPNGatewayID, err)
			return err
		}
	}
	if len(connectionID) == 0 { // if connection doesn't exist, use the one just created
		connectionID = *connectionInterface.(*vpcv1.VPNGatewayConnectionRouteModeVPNGatewayConnectionStaticRouteMode).ID
		utils.Log.Printf("\nCreated VPN connection %v", connectionID)
	}

	// get the routing table of the VPC where the VPN gateway resides
	vpnGateway, _, err := c.vpcService.GetVPNGateway(c.vpcService.NewGetVPNGatewayOptions(VPNGatewayID))
	if err != nil {
		utils.Log.Printf("Failed to get routing table of the VPC containing VPN gateway %v with error: %+v", VPNGatewayID, err)
		return err
	}
	vpcID := *vpnGateway.(*vpcv1.VPNGateway).VPC.ID

	defaultRoutingTable, _, err := c.vpcService.GetVPCDefaultRoutingTable(c.vpcService.NewGetVPCDefaultRoutingTableOptions(vpcID))
	if err != nil {
		utils.Log.Printf("Failed to get default routing table for VPN %v with error: %+v", VPNGatewayID, err)
		return err
	}

	// create routes for all zones in the default routing table of the VPC
	err = c.createRoutes(*defaultRoutingTable.ID, vpcID, connectionID, destinationCIDRs)
	if err != nil {
		utils.Log.Printf("Error occurred while creating routes after deploying VPN connections for VPN %v: %+v", VPNGatewayID, err)
		return err
	}
	return nil
}

// Polls a VPN connection status. Returns an error if connection fails to delete within the alloted time frame.
func (c *CloudClient) pollVPNConnectionDeleted(VPNGatewayID, connectionID string) error {
	delAttempts := 10
	for attempt := 1; attempt <= delAttempts; attempt += 1 {
		vpnGatewayConnectionOptions := c.vpcService.NewGetVPNGatewayConnectionOptions(
			VPNGatewayID,
			connectionID,
		)
		_, _, err := c.vpcService.GetVPNGatewayConnection(vpnGatewayConnectionOptions)
		if err != nil {
			// connection deleted successfully, hence error was raised
			utils.Log.Printf("connection %v deleted successfully in attempt No. %v", connectionID, attempt)
			return nil
		}
		time.Sleep(10 * time.Second)
	}
	return fmt.Errorf("Connection with ID: %v failed to delete in the alloted time frame", connectionID)
}

// Polls a VPN connection status. Returns an error if connection fails to delete within the alloted time frame.
func (c *CloudClient) pollRouteDeleted(vpcID, routingTableID string, route vpcv1.Route) error {
	delAttempts := 10
	routeZone := *route.Zone
	for attempt := 1; attempt <= delAttempts; attempt += 1 {
		options := c.vpcService.NewGetVPCRoutingTableRouteOptions(
			vpcID,
			routingTableID,
			*route.ID,
		)
		_, _, err := c.vpcService.GetVPCRoutingTableRoute(options)

		if err != nil {
			// route deleted successfully
			utils.Log.Printf("route at %v deleted successfully in attempt No. %v", routeZone, attempt)
			return nil
		}
		time.Sleep(10 * time.Second)
	}
	return fmt.Errorf("route named: %v failed to delete in the alloted time frame", *route.Name)
}

// Deletes routes (from the VPC that the specified VPN resides in) directing traffic to the specified connection
func (c *CloudClient) DeleteRoutesDependentOnConnection(VPNGatewayID string, connection *vpcv1.VPNGatewayConnectionRouteModeVPNGatewayConnectionStaticRouteMode) error {

	// get the routing table of the VPC where the VPN gateway resides
	vpnGateway, _, err := c.vpcService.GetVPNGateway(c.vpcService.NewGetVPNGatewayOptions(VPNGatewayID))
	if err != nil {
		utils.Log.Printf("Failed to fetch VPN gateway data for VPN ID %v, during routes deletion process, with error: %+v", VPNGatewayID, err)
		return err
	}
	vpcID := *vpnGateway.(*vpcv1.VPNGateway).VPC.ID
	fmt.Printf("Found VPN gateway in vpc %s\n", vpcID)

	defaultRoutingTable, _, err := c.vpcService.GetVPCDefaultRoutingTable(c.vpcService.NewGetVPCDefaultRoutingTableOptions(vpcID))
	if err != nil {
		utils.Log.Printf("Failed to fetch default routing table for VPC containing VPN ID %v, during routes deletion process, with error: %+v", VPNGatewayID, err)
		return err
	}

	tables, _, err := c.vpcService.ListVPCRoutingTables(&vpcv1.ListVPCRoutingTablesOptions{VPCID: &vpcID})
	if err != nil {
		utils.Log.Printf("Failed to fetch tables for VPC containing VPN ID %v, during routes deletion process, with error: %+v", VPNGatewayID, err)
		return err
	}
	fmt.Printf("Routing tables in VPC : %+v\n", tables.RoutingTables)
	deletedRoutes := []vpcv1.Route{}

	for _, table := range tables.RoutingTables {
		routes, _, err := c.vpcService.ListVPCRoutingTableRoutes(
			&vpcv1.ListVPCRoutingTableRoutesOptions{VPCID: &vpcID, RoutingTableID: table.ID})
		if err != nil {
			utils.Log.Printf("Failed to fetch routes for VPC containing VPN ID %v, during routes deletion process, with error: %+v", VPNGatewayID, err)
			return err
		}
		fmt.Printf("Routing table routes %s : %+v\n", *table.ID, routes.Routes)

		// delete all routes with routing next hop pointing at the specified connection
		for _, route := range routes.Routes {
			fmt.Printf("Deleting VPN route %v\n", *route.ID)
			routeNextHop, isNextHopToVpnConnection := route.NextHop.(*vpcv1.RouteNextHop)
			if !isNextHopToVpnConnection {
				return fmt.Errorf("Expected next hop to reference a VPN connection, instead (likely) references an IP address.")
			}
			if *routeNextHop.ID == *connection.ID {
				_, err = c.vpcService.DeleteVPCRoutingTableRoute(&vpcv1.DeleteVPCRoutingTableRouteOptions{
					VPCID: &vpcID,
					ID:    route.ID,
				})
				if err != nil {
					utils.Log.Printf("Failed to delete VPC route ID %v routing to connection %v, with error: %+v", *route.ID, *connection.ID, err)
					return err
				}
				// keep track of routes set for deletion (directing to the specified connection)
				deletedRoutes = append(deletedRoutes, route)
				fmt.Printf("Deleted VPC route %v directing traffic from %v ", *route.ID, *route.Zone.Name)
			}
		}
	}

	// wait for routes to delete
	for _, route := range deletedRoutes {
		err := c.pollRouteDeleted(vpcID, *defaultRoutingTable.ID, route)
		if err != nil {
			utils.Log.Printf("Error occurred while polling route status for routes in routing table %v, during routes deletion process, with error: %+v", *defaultRoutingTable.ID, err)
			return err
		}
		fmt.Printf("Route deleted %v\n", *route.ID)
	}

	for _, table := range tables.RoutingTables {
		_, err := c.vpcService.DeleteVPCRoutingTable(&vpcv1.DeleteVPCRoutingTableOptions{
			VPCID: &vpcID,
			ID:    table.ID,
		})
		if err != nil {
			utils.Log.Printf("Failed to delete VPC routing table ID %v with error: %+v", *table.ID, err)
			return err
		}
		fmt.Printf("Routing table %s deleted\n", *table.ID)
	}
	time.Sleep(10 * time.Second)
	return nil
}

// deletes the specified VPN along with its connections their associated routes
func (c *CloudClient) DeleteVPN(VPNGatewayID string) error {
	vpnConnections, _, err := c.vpcService.ListVPNGatewayConnections(
		&vpcv1.ListVPNGatewayConnectionsOptions{VPNGatewayID: core.StringPtr(VPNGatewayID)})
	if err != nil {
		utils.Log.Printf("Failed to fetch VPN connections of VPN %v, during VPN deletion process, with error: %+v", VPNGatewayID, err)
		return err
	}

	// invoke delete operation on all VPN connections
	for _, connectionInterface := range vpnConnections.Connections {
		connection := connectionInterface.(*vpcv1.VPNGatewayConnectionRouteModeVPNGatewayConnectionStaticRouteMode)
		// delete routes directing to this connection
		err := c.DeleteRoutesDependentOnConnection(VPNGatewayID, connection)
		if err != nil {
			utils.Log.Printf("Failed to delete routes of VPN connection %v, during VPN deletion process, with error: %+v", *connection.ID, err)
			return err
		}
		fmt.Printf("VPN Routes Deleted\n")
		time.Sleep(10 * time.Second)
		// set connection for deletion
		fmt.Printf("Trying to delete gateway connection connection: %v\n", *connection.ID)
		_, err = c.vpcService.DeleteVPNGatewayConnection(
			&vpcv1.DeleteVPNGatewayConnectionOptions{VPNGatewayID: &VPNGatewayID, ID: connection.ID})

		if err != nil {
			utils.Log.Printf("Failed to delete VPN connection %v, with error: %+v", *connection.ID, err)
			return err
		}
	}

	// wait for connections deletion operation to finalize
	for _, connectionInterface := range vpnConnections.Connections {
		connectionID := *connectionInterface.(*vpcv1.VPNGatewayConnectionRouteModeVPNGatewayConnectionStaticRouteMode).ID
		err = c.pollVPNConnectionDeleted(VPNGatewayID, connectionID)
		if err != nil {
			utils.Log.Printf("Error occurred while polling connection %v status, during VPN deletion process, with error: %+v", connectionID, err)
			return err
		}
		fmt.Printf("VPN Connection %s Deleted\n", connectionID)
	}
	fmt.Printf("VPN Connections Deleted\n")
	time.Sleep(10 * time.Second)

	_, err = c.vpcService.DeleteVPNGateway(&vpcv1.DeleteVPNGatewayOptions{ID: &VPNGatewayID})
	if err != nil {
		utils.Log.Printf("Failed to delete VPN %v, with error: %+v", VPNGatewayID, err)
		return err
	}
	utils.Log.Printf("VPN gateway with ID %v was set for deletion", VPNGatewayID)

	// wait for VPN deletion (can't delete reliant resources such as subnets otherwise)
	err = c.pollVPNStatus(VPNGatewayID, false)
	if err != nil {
		return err
	}

	return nil
}

// return ResourceData object of a VPN gateway matching the specified namespace and region.
// if region value is empty avoid filtering results by region.
func (c *CloudClient) GetVPNsInNamespaceRegion(namespace, region string) ([]resourceData, error) {
	queryFilter := resourceQuery{Region: region}
	// fetch VPN of the specified namespace's region.
	vpns, err := c.GetParagliderTaggedResources(VPN, []string{namespace}, queryFilter)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to fetch VPNs in namespace %v ", namespace)
		if len(region) > 0 {
			errMsg += fmt.Sprintf("in region %v", region)
		}
		utils.Log.Printf(errMsg+" with error: %+v", err)
		return nil, err
	}
	return vpns, nil
}

// returns an IKE policy ID that's compatible with the specified peer cloud
func (c *CloudClient) getOrCreateIKEPolicy(peerCloud string) (*string, error) {
	// return an existing IPSec policy for the specified cloud if one exists in the region
	existingPolicy, err := c.getIKEPolicy(peerCloud)
	if err != nil {
		utils.Log.Printf("Error occurred while looking for an existing IKEPolicy policy for cloud %v: %+v", peerCloud, err)
		return nil, err
	}
	if existingPolicy != nil {
		utils.Log.Printf("Using existing IKE policy %v in region %v", *existingPolicy.Name, c.region)
		return existingPolicy.ID, nil
	}

	// create a new IKE policy for specified cloud
	config := &vpcv1.CreateIkePolicyOptions{
		Name:          core.StringPtr(generateResourceName("ike-" + peerCloud)),
		IkeVersion:    core.Int64Ptr(2),
		ResourceGroup: c.resourceGroup,
	}
	if peerCloud == utils.AZURE {
		config.SetAuthenticationAlgorithm(vpcv1.CreateIkePolicyOptionsAuthenticationAlgorithmSha384Const)
		config.SetDhGroup(24)
		config.SetEncryptionAlgorithm(vpcv1.CreateIkePolicyOptionsEncryptionAlgorithmAes256Const)
		config.SetKeyLifetime(27000)
	}

	ikePolicy, _, err := c.vpcService.CreateIkePolicy(config)
	if err != nil {
		utils.Log.Printf("Failed to create IKEPolicy policy for cloud %v, with error: %+v", peerCloud, err)
		return nil, err
	}

	return ikePolicy.ID, nil
}

// returns existing IKE policy for the peer cloud
func (c *CloudClient) getIKEPolicy(peerCloud string) (*vpcv1.IkePolicy, error) {
	ikePolicies, _, err := c.vpcService.ListIkePolicies(&vpcv1.ListIkePoliciesOptions{})
	if err != nil {
		utils.Log.Printf("Failed to list existing IKEPolicies policies for cloud %v, with error: %+v", peerCloud, err)
		return nil, err
	}
	for _, policy := range ikePolicies.IkePolicies {
		if strings.Contains(*policy.Name, peerCloud) {
			return &policy, nil
		}
	}
	// no policy matching the specified cloud was found
	return nil, nil
}

// returns an IPsec policy ID that's compatible with the specified peer cloud
func (c *CloudClient) getOrCreateIPSecPolicy(peerCloud string) (*string, error) {
	// return an existing IPSec policy for the specified cloud if one exists in the region
	existingPolicy, err := c.getIPSecPolicy(peerCloud)
	if err != nil {
		utils.Log.Printf("Error occurred while looking for an existing IPSec policy for cloud %v: %+v", peerCloud, err)
		return nil, err
	}
	if existingPolicy != nil {
		utils.Log.Printf("Using existing IPSec policy %v in region %v", *existingPolicy.Name, c.region)
		return existingPolicy.ID, nil
	}

	// create a new IPSec policy for specified cloud
	config := &vpcv1.CreateIpsecPolicyOptions{
		Name:          core.StringPtr(generateResourceName("ipsec-" + peerCloud)),
		ResourceGroup: c.resourceGroup,
	}
	if peerCloud == utils.AZURE {
		config.SetAuthenticationAlgorithm("sha256")
		config.SetEncryptionAlgorithm("aes256")
		config.SetKeyLifetime(27000)
		config.SetPfs(vpcv1.CreateIpsecPolicyOptionsPfsDisabledConst) // disable perfect forward secrecy
	}
	ipsecPolicy, _, err := c.vpcService.CreateIpsecPolicy(config)
	if err != nil {
		utils.Log.Printf("Failed to create IPSec policy for cloud %v, with error: %+v", peerCloud, err)
		return nil, err
	}

	return ipsecPolicy.ID, nil
}

// returns existing IPSec policy for the peer cloud
func (c *CloudClient) getIPSecPolicy(peerCloud string) (*vpcv1.IPsecPolicy, error) {
	ipSecPolicies, _, err := c.vpcService.ListIpsecPolicies(&vpcv1.ListIpsecPoliciesOptions{})
	if err != nil {
		utils.Log.Printf("Failed to list existing IPSec policies for cloud %v, with error: %+v", peerCloud, err)
		return nil, err
	}
	for _, policy := range ipSecPolicies.IpsecPolicies {
		if strings.Contains(*policy.Name, peerCloud) {
			return &policy, nil
		}
	}
	// no policy matching the specified cloud was found
	return nil, nil
}

// returns the first available priority that doesn't cause a routing conflict.
// if rule exists, returns false.
// - routing conflict - occurs when 2 rules share the same zone, destination and priority.
// - rule duplication - if specified rule matches a rule on the following fields: destination, zone and nextHopConnection.
func (c *CloudClient) getAvailablePriority(routeData *vpcv1.CreateVPCRoutingTableRouteOptions) (bool, int64, error) {

	const numOfPriorities = 5
	// keeps tracks of available priorities for given rule, e.g. if rule[i]==false, priority i isn't available.
	availablePriority := make(map[int64]bool, numOfPriorities)
	for i := 0; i < numOfPriorities; i++ {
		availablePriority[int64(i)] = true
	}
	options := c.vpcService.NewListVPCRoutingTableRoutesOptions(
		*routeData.VPCID,
		*routeData.RoutingTableID,
	)

	routeCollection, _, err := c.vpcService.ListVPCRoutingTableRoutes(options)
	if err != nil {
		utils.Log.Printf("Failed to get routes of routing table %v of VPC %v,while mapping available priorities, with error: %+v", *routeData.RoutingTableID, *routeData.VPCID, err)
		return false, -1, err
	}
	routeDestination := *routeData.Destination
	routeZone := *routeData.Zone.(*vpcv1.ZoneIdentityByName).Name
	routeConnectionID := *routeData.NextHop.(*vpcv1.RoutePrototypeNextHop).ID

	for _, route := range routeCollection.Routes {
		// check if rule exists
		if *route.Destination == routeDestination && *route.Zone.Name == routeZone &&
			*route.NextHop.(*vpcv1.RouteNextHop).ID == routeConnectionID {
			// rule already exists, return
			return true, -1, nil
		}
		// if a route that shares the same zone and destination, its priority isn't available for the specified route
		if *route.Zone.Name == routeZone && *route.Destination == routeDestination {
			availablePriority[*route.Priority] = false
		}
	}

	for priority, isAvailable := range availablePriority {
		if isAvailable {
			return false, priority, nil
		}
	}

	// rule doesn't exist, but no available priority found
	return false, -1, fmt.Errorf("No available priority found to create a route in zone: %v, destination: %v, to connectionID: %v", routeZone, routeDestination, routeConnectionID)
}
