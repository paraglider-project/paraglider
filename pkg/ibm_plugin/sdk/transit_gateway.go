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

	"github.com/IBM/go-sdk-core/core"
	"github.com/IBM/networking-go-sdk/transitgatewayapisv1"
	"github.com/google/uuid"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

type TransitConnection struct {
	ID     string // connection's ID
	Name   string // connection's name
	VPCCRN string // CRN of the connected VPC
}

const (
	connectionType = "connection"
)

// creates a global transit gateway (global routing) at the specified region and
// tags it with the specified namespace
func (c *CloudClient) CreateTransitGW(region string) (*transitgatewayapisv1.TransitGateway, error) {
	createTransitGatewayOptions := &transitgatewayapisv1.CreateTransitGatewayOptions{
		Location:      &region, // location is mandatory even on global transmit GW.
		Global:        core.BoolPtr(true),
		ResourceGroup: (*transitgatewayapisv1.ResourceGroupIdentity)(c.resourceGroup),
		Name:          core.StringPtr("Paraglider-transit-gw-" + uuid.New().String()[:8])}
	transitGateway, _, err := c.transitGW.CreateTransitGateway(createTransitGatewayOptions)
	if err != nil {
		return nil, err
	}
	utils.Log.Printf("created transit GW named %v with ID: %v", *transitGateway.Name, *transitGateway.ID)

	// tag the transitGW with the namespace
	err = c.attachTag(transitGateway.Crn, []string{})
	if err != nil {
		return nil, err
	}

	return transitGateway, nil
}

// returns connections of the transit gateway
func (c *CloudClient) GetTransitGWConnections(gwID string) ([]TransitConnection, error) {
	var connections []TransitConnection
	listTransitGatewayConnectionsOptions := c.transitGW.NewListTransitGatewayConnectionsOptions(gwID)
	transitGatewayConnectionCollection, _, err := c.transitGW.ListTransitGatewayConnections(listTransitGatewayConnectionsOptions)
	if err != nil {
		return connections, err
	}
	for _, connection := range transitGatewayConnectionCollection.Connections {
		connections = append(connections,
			TransitConnection{ID: *connection.ID, Name: *connection.Name, VPCCRN: *connection.NetworkID})
	}

	return connections, nil
}

// adds VPC as a connection to an existing Transit Gateway
func (c *CloudClient) AddTransitGWConnection(transitGatewayID string, vpcCRN string) (TransitConnection, error) {
	connectionName := GenerateResourceName(connectionType)
	createConnectionOptions := &transitgatewayapisv1.CreateTransitGatewayConnectionOptions{
		TransitGatewayID: &transitGatewayID,
		NetworkType:      core.StringPtr(transitgatewayapisv1.CreateTransitGatewayConnectionOptions_NetworkType_Vpc),
		NetworkID:        &vpcCRN,
		Name:             &connectionName,
	}
	res, _, err := c.transitGW.CreateTransitGatewayConnection(createConnectionOptions)
	if err != nil {
		return TransitConnection{}, err
	}
	utils.Log.Printf("Added a connection to TGW ID: %v with result: %+v", transitGatewayID, res)

	return TransitConnection{ID: *res.ID, Name: *res.Name, VPCCRN: *res.NetworkID}, nil
}

// deletes a gateway matching the specified ID
func (c *CloudClient) DeleteTransitGW(gwID string) error {
	// gateway's connection must be removed before the GW can be deleted
	err := c.RemoveTransitGWConnections(gwID)
	if err != nil {
		return err
	}

	// delete the transit gateway
	deleteTransitGatewayOptions := &transitgatewayapisv1.DeleteTransitGatewayOptions{
		ID: &gwID,
	}
	res, err := c.transitGW.DeleteTransitGateway(deleteTransitGatewayOptions)
	if err != nil {
		utils.Log.Printf("failed to delete transit gateway %v with error: %v and response:\n%+v", gwID, err, res)
		return err
	}
	utils.Log.Printf("deleted transit gateway %v with result:\n%+v", gwID, res)
	return nil
}

// removes connections attached to gateway. returns only when all connections removed.
func (c *CloudClient) RemoveTransitGWConnections(gwID string) error {
	connections, err := c.GetTransitGWConnections(gwID)
	if err != nil {
		return err
	}
	// start deletion process on all connections
	for _, connection := range connections {
		err = c.RemoveTransitGWConnection(connection.ID, gwID)
		if err != nil {
			return err
		}
	}
	// wait for connection's deletion process to end
	for _, connection := range connections {
		if conDeleted, err := c.pollConnectionDeleted(connection.ID, gwID); !conDeleted || err != nil {
			return err
		}
	}
	return nil
}

// returns true if connection was deleted within the alloted time, otherwise false.
func (c *CloudClient) pollConnectionDeleted(connectionID string, gwID string) (bool, error) {
	delAttempts := 10
	transitGatewayConnectionOptions := c.transitGW.NewGetTransitGatewayConnectionOptions(
		gwID,
		connectionID,
	)
	// the following is a blocking polling mechanism that returns when the GW is deleted/alloted time has past.
	for attempt := 1; attempt <= delAttempts; attempt += 1 {
		_, _, err := c.transitGW.GetTransitGatewayConnection(transitGatewayConnectionOptions)
		if err != nil {
			// connection deleted successfully, hence not found error raised
			utils.Log.Printf("connection deleted successfully in attempt No. %v", attempt)
			return true, nil
		}
		// sleep to avoid busy waiting
		time.Sleep(10 * time.Second)
	}
	return false, fmt.Errorf("Connection with ID: %v wasn't deleted in the alloted time frame", connectionID)
}

// removes the specified connection from the specified transit gateway.
func (c *CloudClient) RemoveTransitGWConnection(connection string, transitGW string) error {

	deleteConnectionOptions := &transitgatewayapisv1.DeleteTransitGatewayConnectionOptions{
		TransitGatewayID: &transitGW,
		ID:               &connection,
	}
	_, err := c.transitGW.DeleteTransitGatewayConnection(deleteConnectionOptions)
	if err != nil {
		return err
	}

	return nil
}

// Connects vpc to the specified transit gateway. ignores error if already connected.
func (c *CloudClient) ConnectVPC(gatewayID string, vpcCRN string) error {
	_, err := c.AddTransitGWConnection(gatewayID, vpcCRN)
	if err == nil {
		return nil
	}
	// must check error message, since error returned isn't a custom type.
	if strings.Contains(err.Error(), "network is already connected") {
		utils.Log.Printf("VPC %v is already connected to gateway ID %v", vpcCRN, gatewayID)
		return nil
	}
	// failed to connect vpc to the transit gateway due to unexpected reason
	return err
}

// returns an ID for an existent global transit gateway. If doesn't exist, creates one in the specified region.
// NOTE: the region argument isn't relevant for the lookup process.
func (c *CloudClient) GetOrCreateTransitGateway(region string) (string, error) {
	// if exists, fetch the transit gateway
	TransitGatewayRes, err := c.GetParagliderTaggedResources(GATEWAY, []string{}, ResourceQuery{})
	if err != nil {
		return "", err
	}
	if len(TransitGatewayRes) == 1 {
		// an paraglider deployment has a single Transit gateway
		utils.Log.Printf("Found an existing transit gateway %+v", TransitGatewayRes[0])
		return TransitGatewayRes[0].ID, nil
	} else if len(TransitGatewayRes) == 0 {
		// create a transit gateway
		gateway, err := c.CreateTransitGW(region)
		if err != nil {
			return "", err
		}
		return *gateway.ID, nil
	}
	return "", fmt.Errorf("encountered an unexpected result:"+
		"%v TGW were found instead of one", len(TransitGatewayRes))
}
