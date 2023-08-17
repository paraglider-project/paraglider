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
	"fmt"
	"net/http"
	"context"
	"strconv"
	"strings"
	"errors"
	// "gopkg.in/yaml.v2"
	"encoding/json"

	"github.com/gin-gonic/gin"

	grpc "google.golang.org/grpc"
	insecure "google.golang.org/grpc/credentials/insecure"

	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
)

type Cloud struct {
	Name string `yaml:"name"`
	Host string `yaml:"host"`
	Port string `yaml:"port"`
}

type Config struct {
    Server struct {
        Port string `yaml:"port"`
        Host string `yaml:"host"`
    } `yaml:"server"`

	Clouds []Cloud `yaml:"cloudPlugins"`
}

// TODO @smcclure20: refactor this to make it more parallel-friendly
var pluginAddresses =  map[string]string{}
var addressSpaceMap =  map[string]string{}
var config Config

func createErrorResponse(message string) gin.H {
	return gin.H{"error": message}
}

// Get specified PermitList from given cloud
func permitListGet(c *gin.Context) {
	id := c.Param("id")
	cloud := c.Param("cloud")

	// Ensure correct cloud name
	cloudClient, ok := pluginAddresses[cloud]
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
func permitListRulesAdd(c *gin.Context) {
	// Ensure correct cloud name 
	cloud := c.Param("cloud")
	cloudClient, ok := pluginAddresses[cloud]
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
func permitListRulesDelete(c *gin.Context) {
	// Ensure correct cloud name 
	cloud := c.Param("cloud")
	cloudClient, ok := pluginAddresses[cloud]
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
func getAddressSpaces(c context.Context, cloud string, deploymentId string) (*invisinetspb.AddressSpaceList, error) {
	// Ensure correct cloud name
	cloudClient, ok := pluginAddresses[cloud]
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
func updateAddressSpaceMap(c context.Context, id string) error {
	// Call each cloud to get address spaces used
	for _, cloud := range config.Clouds {
		addressMap, err := getAddressSpaces(c, cloud.Name, id)
		if err != nil {
			return fmt.Errorf("Could not retrieve address spaces for cloud %s", cloud)
		}

		// Store address space by <cloud_name>\<region>
		for _, cloudRegion := range addressMap.Mappings {
			addressSpaceMap[cloud.Name + "\\" + cloudRegion.Region] = cloudRegion.AddressSpace
		}
	}
	return nil
}

// Get a new address block for a new virtual network
// TODO @smcclure20: Later, this should allocate more efficiently and with different size address blocks (eg, GCP needs larger than Azure since a VPC will span all regions)
func getNewAddressSpace(c context.Context) (string, error) {
	highestBlockUsed := -1
	for _, address := range addressSpaceMap {
		blockNumber, err := strconv.Atoi(strings.Split(address, ".")[1])
		if err != nil {
			return "", err
		}

		if blockNumber > highestBlockUsed {
			highestBlockUsed = blockNumber
		}
	}

	if highestBlockUsed >= 255 {
		return "", errors.New("All address blocks used")
	}

	return fmt.Sprintf("10.%d.0.0/16", highestBlockUsed + 1), nil
}

// Create resource in specified cloud region
func resourceCreate(c *gin.Context) {
	// Ensure correct cloud name
	cloud := c.Param("cloud")
	cloudClient, ok := pluginAddresses[cloud]
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

	// Check the resource region and get corresponding address space from it or get a new address space
	err := updateAddressSpaceMap(context.Background(), resourceWithString.Id)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	region := c.Param("region")
	addressSpace, ok := addressSpaceMap[region]
	if !ok {
		// Create a new address space 
		newAddressSpace, err := getNewAddressSpace(context.Background())
		if err != nil {
			c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
			return
		}
		addressSpace = newAddressSpace
	}

	// Create connection to cloud plugin
	conn, err := grpc.Dial(cloudClient, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()

	// Send RPC to create the resource
	resource :=  invisinetspb.ResourceDescription{Id: resourceWithString.Id, Description: []byte(resourceWithString.Description), AddressSpace: addressSpace}
	client := invisinetspb.NewCloudPluginClient(conn)
	response, err := client.CreateResource(context.Background(), &resource)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
	}

	c.JSON(http.StatusOK, gin.H{
		"response": response.Message,
		"addressSpace": addressSpace,
	})
}

// TODO @smcclure20: include for later integration with cli to run server
// func setup(configPath string) {

// 	f, err := os.Open(configPath)
// 	if err != nil {
// 		fmt.Println(err.Error())
// 	}
// 	defer f.Close()

// 	var cfg Config
// 	decoder := yaml.NewDecoder(f)
// 	err = decoder.Decode(&cfg)
// 	if err != nil {
// 		fmt.Println(err.Error())
// 	}
// 	config = cfg

// 	for _, c := range config.Clouds {
// 		pluginAddresses[c.Name] = c.Host + ":" + c.Port
// 	}

// 	router := gin.Default()
// 	router.GET("/ping", func(c *gin.Context) {
// 		c.JSON(http.StatusOK, gin.H{
// 			"message": "pong",
// 		})
// 	})

// 	router.GET("/cloud/:cloud/resources/:id/permit-list/", permitListGet)
// 	router.POST("/cloud/:cloud/resources/:id/permit-list/rules/", permitListRulesAdd)
// 	router.DELETE("/cloud/:cloud/resources/:id/permit-list/rules/", permitListRulesDelete)
// 	router.POST("/cloud/:cloud/region/:region/resources/:id/", resourceCreate)
  
// 	err = router.Run(config.Server.Host + ":" + config.Server.Port)
// 	if err != nil {
// 		fmt.Println(err.Error())
// 	}
// }
