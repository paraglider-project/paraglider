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

package frontend

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/gin-gonic/gin"

	grpc "google.golang.org/grpc"
	insecure "google.golang.org/grpc/credentials/insecure"

	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	utils "github.com/NetSys/invisinets/pkg/utils"
)

// Configuration structs
type Cloud struct {
	Name          string `yaml:"name"`
	Host          string `yaml:"host"`
	Port          string `yaml:"port"`
	InvDeployment string `yaml:"invDeployment"`
}

type Config struct {
	Server struct {
		Port string `yaml:"port"`
		Host string `yaml:"host"`
	} `yaml:"server"`

	Clouds []Cloud `yaml:"cloudPlugins"`
}

type ControllerServer struct {
	invisinetspb.UnimplementedControllerServer
	pluginAddresses   map[string]string
	usedAddressSpaces map[string][]string
	config            Config
}

func createErrorResponse(message string) gin.H {
	return gin.H{"error": message}
}

// Get specified PermitList from given cloud
func (s *ControllerServer) permitListGet(c *gin.Context) {
	id := c.Param("id")
	cloud := c.Param("cloud")

	// Ensure correct cloud name
	cloudClient, ok := s.pluginAddresses[cloud]
	if !ok {
		c.AbortWithStatusJSON(400, createErrorResponse(fmt.Sprintf("Invalid cloud name: %s", cloud)))
		return
	}

	// Connect to the cloud plugin
	conn, err := grpc.Dial(cloudClient, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()

	// Send the GetPermitList RPC
	client := invisinetspb.NewCloudPluginClient(conn)
	emptyresourceId := invisinetspb.ResourceID{Id: id}

	response, err := client.GetPermitList(context.Background(), &emptyresourceId)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Read the response and send back to original client
	pl_json, err := json.Marshal(response)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":              id,
		"resource":        response.AssociatedResource,
		"permitlist_json": string(pl_json[:]),
	})
}

// Add permit list rules to specified resource
func (s *ControllerServer) permitListRulesAdd(c *gin.Context) {
	// Ensure correct cloud name
	cloud := c.Param("cloud")
	cloudClient, ok := s.pluginAddresses[cloud]
	if !ok {
		c.AbortWithStatusJSON(400, createErrorResponse("Invalid cloud name"))
		return
	}

	// Parse permit list rules to add
	var permitListRules invisinetspb.PermitList
	if err := c.BindJSON(&permitListRules); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Create connection to cloud plugin
	conn, err := grpc.Dial(cloudClient, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()

	// Send RPC to create rules
	client := invisinetspb.NewCloudPluginClient(conn)
	response, err := client.AddPermitListRules(context.Background(), &permitListRules)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
	}

	c.JSON(http.StatusOK, gin.H{
		"response": response.Message,
	})
}

// Delete permit list rules to specified resource
func (s *ControllerServer) permitListRulesDelete(c *gin.Context) {
	// Ensure correct cloud name
	cloud := c.Param("cloud")
	cloudClient, ok := s.pluginAddresses[cloud]
	if !ok {
		c.AbortWithStatusJSON(400, createErrorResponse("Invalid cloud name"))
		return
	}

	// Parse rules to delete
	var permitListRules invisinetspb.PermitList
	if err := c.BindJSON(&permitListRules); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Create connection to cloud plugin
	conn, err := grpc.Dial(cloudClient, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()

	// Send RPC to delete the rules
	client := invisinetspb.NewCloudPluginClient(conn)
	response, err := client.DeletePermitListRules(context.Background(), &permitListRules)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
	}

	c.JSON(http.StatusOK, gin.H{
		"response": response.Message,
	})
}

// Get used address spaces from a specified cloud
func (s *ControllerServer) getAddressSpaces(cloud string, deploymentId string) (*invisinetspb.AddressSpaceList, error) {
	// Ensure correct cloud name
	cloudClient, ok := s.pluginAddresses[cloud]
	if !ok {
		return nil, errors.New("Invalid cloud name")
	}

	// Connect to cloud plugin
	conn, err := grpc.Dial(cloudClient, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("Unable to connect to cloud plugin: %s", err.Error())
	}
	defer conn.Close()

	// Send the RPC to get the address spaces
	client := invisinetspb.NewCloudPluginClient(conn)
	deployment := invisinetspb.InvisinetsDeployment{Id: deploymentId}
	addressSpaces, err := client.GetUsedAddressSpaces(context.Background(), &deployment)

	return addressSpaces, err
}

// Update local address space map by getting used address spaces from each cloud plugin
func (s *ControllerServer) updateUsedAddressSpacesMap() error {
	// Call each cloud to get address spaces used
	for _, cloud := range s.config.Clouds {
		addressList, err := s.getAddressSpaces(cloud.Name, cloud.InvDeployment)
		if err != nil {
			return fmt.Errorf("Could not retrieve address spaces for cloud %s", cloud)
		}

		s.usedAddressSpaces[cloud.Name] = addressList.AddressSpaces
	}
	return nil
}

// Get a new address block for a new virtual network
// TODO @smcclure20: Later, this should allocate more efficiently and with different size address blocks (eg, GCP needs larger than Azure since a VPC will span all regions)
func (s *ControllerServer) FindUnusedAddressSpace(c context.Context, e *invisinetspb.Empty) (*invisinetspb.AddressSpace, error) {
	err := s.updateUsedAddressSpacesMap()
	if err != nil {
		return nil, err
	}
	highestBlockUsed := -1
	for _, addressList := range s.usedAddressSpaces {
		for _, address := range addressList {
			blockNumber, err := strconv.Atoi(strings.Split(address, ".")[1])
			if err != nil {
				return nil, err
			}
			if blockNumber > highestBlockUsed {
				highestBlockUsed = blockNumber
			}
		}
	}

	if highestBlockUsed >= 255 {
		return nil, errors.New("All address blocks used")
	}

	newAddressSpace := &invisinetspb.AddressSpace{Address: fmt.Sprintf("10.%d.0.0/16", highestBlockUsed+1)} // if changing this to something other than /16, make sure to change the azureSDKHandler.CreateInvisinetsVirtualNetwork accordingly for partitioning the address space
	return newAddressSpace, nil
}

// Gets unused address spaces across all clouds
func (s *ControllerServer) GetUsedAddressSpaces(c context.Context, e *invisinetspb.Empty) (*invisinetspb.AddressSpaceMappingList, error) {
	err := s.updateUsedAddressSpacesMap()
	if err != nil {
		return nil, err
	}

	usedAddressSpaceMappings := &invisinetspb.AddressSpaceMappingList{}
	usedAddressSpaceMappings.AddressSpaceMappings = make([]*invisinetspb.AddressSpaceMapping, len(s.usedAddressSpaces))
	i := 0
	for cloud, addressSpaces := range s.usedAddressSpaces {
		usedAddressSpaceMappings.AddressSpaceMappings[i] = &invisinetspb.AddressSpaceMapping{
			AddressSpaces: addressSpaces,
			Cloud:         cloud,
		}
		i++
	}

	return usedAddressSpaceMappings, nil
}

// Generates 32-byte shared key for VPN connections
func generateSharedKey() (string, error) {
	key := make([]byte, 24)
	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("unable to get random bytes: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// Gets the Invisinets deployment field of a cloud
// TODO @seankimkdy: make this more efficient by using maps to maintain clouds in config?
func (s *ControllerServer) getCloudInvDeployment(cloudName string) string {
	for _, cloud := range s.config.Clouds {
		if cloud.Name == cloudName {
			return cloud.InvDeployment
		}
	}
	return ""
}

// Connects two clouds with VPN gateways
func (s *ControllerServer) ConnectClouds(ctx context.Context, req *invisinetspb.ConnectCloudsRequest) (*invisinetspb.BasicResponse, error) {
	// TODO @seankimkdy: have better checking of which clouds are supported for multicloud connections
	// TODO @seankimkdy: cloudA and cloudB naming seems to be very prone to typos, so perhaps use another naming scheme[?
	if (req.CloudA == utils.GCP && req.CloudB == utils.AZURE) || (req.CloudA == utils.AZURE && req.CloudB == utils.GCP) {
		cloudAClientAddress, ok := s.pluginAddresses[req.CloudA]
		if !ok {
			return nil, fmt.Errorf("invalid cloud name: %s", req.CloudA)
		}
		cloudAConn, err := grpc.Dial(cloudAClientAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, fmt.Errorf("unable to connect to cloud plugin: %w", err)
		}
		defer cloudAConn.Close()
		cloudAClient := invisinetspb.NewCloudPluginClient(cloudAConn)

		cloudBClientAddress, ok := s.pluginAddresses[req.CloudB]
		if !ok {
			return nil, fmt.Errorf("invalid cloud name: %s", req.CloudA)
		}
		cloudBconn, err := grpc.Dial(cloudBClientAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, fmt.Errorf("Unable to connect to cloud plugin: %w", err)
		}
		defer cloudAConn.Close()
		cloudBClient := invisinetspb.NewCloudPluginClient(cloudBconn)

		ctx := context.Background()

		cloudAInvisinetsDeployment := &invisinetspb.InvisinetsDeployment{Id: s.getCloudInvDeployment(req.CloudA)}
		cloudACreateVpnGatewayResp, err := cloudAClient.CreateVpnGateway(ctx, cloudAInvisinetsDeployment)
		if err != nil {
			return nil, fmt.Errorf("unable to create vpn gateway in cloud %s: %w", req.CloudA, err)
		}
		cloudBInvisinetsDeployment := &invisinetspb.InvisinetsDeployment{Id: s.getCloudInvDeployment(req.CloudB)}
		cloudBCreateVpnGatewayResp, err := cloudBClient.CreateVpnGateway(ctx, cloudBInvisinetsDeployment)
		if err != nil {
			return nil, fmt.Errorf("unable to create vpn gateway in cloud %s: %w", req.CloudB, err)
		}

		cloudACreateVpnBgpSessionsReq := &invisinetspb.CreateVpnBgpSessionsRequest{
			Deployment: cloudAInvisinetsDeployment,
			Cloud:      req.CloudB,
		}
		cloudACreateVpnBgpSessionsResp, err := cloudAClient.CreateVpnBgpSessions(ctx, cloudACreateVpnBgpSessionsReq)
		if err != nil {
			return nil, fmt.Errorf("unable to create vpn bgp sessions in cloud %s: %w", req.CloudA, err)
		}
		cloudBCreateVpnBgpSessionsReq := &invisinetspb.CreateVpnBgpSessionsRequest{
			Deployment: cloudBInvisinetsDeployment,
			Cloud:      req.CloudA,
		}
		cloudBCreateVpnBgpSessionsResp, err := cloudBClient.CreateVpnBgpSessions(ctx, cloudBCreateVpnBgpSessionsReq)
		if err != nil {
			return nil, fmt.Errorf("unable to create vpn bgp sessions in cloud %s: %w", req.CloudA, err)
		}

		sharedKey, err := generateSharedKey()
		if err != nil {
			return nil, fmt.Errorf("unable to generate shared key: %w", err)
		}

		cloudACreateVpnConnectionsReq := &invisinetspb.CreateVpnConnectionsRequest{
			Deployment:         cloudAInvisinetsDeployment,
			Cloud:              req.CloudB,
			Asn:                cloudBCreateVpnGatewayResp.Asn,
			AddressSpace:       req.CloudBAddressSpace,
			GatewayIpAddresses: cloudBCreateVpnGatewayResp.GatewayIpAddresses,
			BgpIpAddresses:     cloudBCreateVpnBgpSessionsResp.BgpIpAddresses,
			SharedKey:          sharedKey,
		}
		_, err = cloudAClient.CreateVpnConnections(ctx, cloudACreateVpnConnectionsReq)
		if err != nil {
			return nil, fmt.Errorf("unable to create vpn connections in cloud %s: %w", req.CloudA, err)
		}
		cloudBCreateVpnConnectionsReq := &invisinetspb.CreateVpnConnectionsRequest{
			Deployment:         cloudBInvisinetsDeployment,
			Cloud:              req.CloudA,
			Asn:                cloudACreateVpnGatewayResp.Asn,
			AddressSpace:       req.CloudAAddressSpace,
			GatewayIpAddresses: cloudACreateVpnGatewayResp.GatewayIpAddresses,
			BgpIpAddresses:     cloudACreateVpnBgpSessionsResp.BgpIpAddresses,
			SharedKey:          sharedKey,
		}
		_, err = cloudBClient.CreateVpnConnections(ctx, cloudBCreateVpnConnectionsReq)
		if err != nil {
			return nil, fmt.Errorf("unable to create vpn connections in cloud %s: %w", req.CloudB, err)
		}
		return &invisinetspb.BasicResponse{Success: true}, nil
	}
	return nil, fmt.Errorf("clouds %s and %s are not supported for multi-cloud connecting", req.CloudA, req.CloudB)
}

// Create resource in specified cloud region
func (s *ControllerServer) resourceCreate(c *gin.Context) {
	// Ensure correct cloud name
	cloud := c.Param("cloud")
	cloudClient, ok := s.pluginAddresses[cloud]
	if !ok {
		c.AbortWithStatusJSON(400, createErrorResponse("Invalid cloud name"))
		return
	}

	// Parse the resource description provided
	var resourceWithString invisinetspb.ResourceDescriptionString
	if err := c.BindJSON(&resourceWithString); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Create connection to cloud plugin
	conn, err := grpc.Dial(cloudClient, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()

	// Send RPC to create the resource
	resource := invisinetspb.ResourceDescription{Id: resourceWithString.Id, Description: []byte(resourceWithString.Description)}
	client := invisinetspb.NewCloudPluginClient(conn)
	response, err := client.CreateResource(context.Background(), &resource)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
	}

	c.JSON(http.StatusOK, gin.H{
		"response": response.Message,
	})
}

func Setup(configPath string) {
	// Read the config
	f, err := os.Open(configPath)
	if err != nil {
		fmt.Println(err.Error())
	}
	defer f.Close()

	var cfg Config
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		fmt.Println(err.Error())
	}

	// Populate server info
	server := ControllerServer{pluginAddresses: make(map[string]string), usedAddressSpaces: make(map[string][]string)}
	server.config = cfg

	for _, c := range server.config.Clouds {
		server.pluginAddresses[c.Name] = c.Host + ":" + c.Port
	}

	// Setup URL router
	router := gin.Default()
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	router.GET("/cloud/:cloud/resources/:id/permit-list/", server.permitListGet)
	router.POST("/cloud/:cloud/resources/:id/permit-list/rules/", server.permitListRulesAdd)
	router.DELETE("/cloud/:cloud/resources/:id/permit-list/rules/", server.permitListRulesDelete)
	router.POST("/cloud/:cloud/resources/:id/", server.resourceCreate)

	// Run server
	err = router.Run(server.config.Server.Host + ":" + server.config.Server.Port)
	if err != nil {
		fmt.Println(err.Error())
	}
}
