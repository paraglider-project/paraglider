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

package main

import (
	"fmt"
	"net/http"
	"context"
	"os"
	"strconv"
	"strings"
	"gopkg.in/yaml.v2"
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

var pluginAddresses =  map[string]string{}
var addressSpaceMap =  map[string]string{}
var config Config

func createErrorResponse(rid string, message string) gin.H {
	fmt.Println(message)
	return gin.H{"id": rid, "err": message}
}

func permitListGet(c *gin.Context) {
	id := c.Param("id")
	cloud := c.Param("cloud")
	cloudClient, ok := pluginAddresses[cloud]
	if !ok {
		c.AbortWithStatusJSON(400, createErrorResponse(id, "Invalid cloud name"))
	}

	emptyresourceId := invisinetspb.ResourceID{Id: id}

	conn, err := grpc.Dial(cloudClient, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return
	}

	client := invisinetspb.NewCloudPluginClient(conn)

	response, err := client.GetPermitList(context.Background(), &emptyresourceId)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
	}

	defer conn.Close()

	pl_json, err := json.Marshal(response)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":              id,
		"permitlist":      response.AssociatedResource,
		"permitlist_json": string(pl_json[:]),
	})
}

func permitListRulesAdd(c *gin.Context) {
	id := c.Param("id")
	cloud := c.Param("cloud")
	cloudClient, ok := pluginAddresses[cloud]
	if !ok {
		c.AbortWithStatusJSON(400, createErrorResponse(id, "Invalid cloud name"))
	}

	var permitListRules invisinetspb.PermitList

	if err := c.BindJSON(&permitListRules); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return
	}

	conn, err := grpc.Dial(cloudClient, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return
	}

	client := invisinetspb.NewCloudPluginClient(conn)

	response, err := client.AddPermitListRules(context.Background(), &permitListRules)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
	}

	defer conn.Close()

	c.JSON(http.StatusOK, gin.H{
		"id":       id,
		"response": response.Message,
	})
}

func permitListRulesDelete(c *gin.Context) {
	id := c.Param("id")
	cloud := c.Param("cloud")
	cloudClient, ok := pluginAddresses[cloud]
	if !ok {
		c.AbortWithStatusJSON(400, createErrorResponse(id, "Invalid cloud name"))
	}

	var permitListRules invisinetspb.PermitList

	if err := c.BindJSON(&permitListRules); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return
	}

	conn, err := grpc.Dial(cloudClient, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return 
	}

	client := invisinetspb.NewCloudPluginClient(conn)

	response, err := client.DeletePermitListRules(context.Background(), &permitListRules)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
	}

	defer conn.Close()

	c.JSON(http.StatusOK, gin.H{
		"id":       id,
		"response": response.Message,
	})
}

func getAddressSpaces(c *gin.Context, cloud string, id string) *invisinetspb.AddressSpaceList {
	cloudClient, ok := pluginAddresses[cloud]
	if !ok {
		fmt.Println("Invalid cloud name")
		c.AbortWithStatusJSON(400, createErrorResponse(id, "Invalid cloud name")) // TODO: is the ID even helpful at this depth? --> OR at all????
		return nil
	}
	
	deployment := invisinetspb.InvisinetsDeployment{Id: id}

	conn, err := grpc.Dial(cloudClient, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Println("Connection failed")
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return nil
	}

	client := invisinetspb.NewCloudPluginClient(conn)

	addressSpaces, err := client.GetUsedAddressSpaces(context.Background(), &deployment)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
	}

	defer conn.Close()

	return addressSpaces
}

func updateAddressSpaceMap(c *gin.Context, id string) {
	// Call each cloud to get address spaces used
	for _, cloud := range config.Clouds {
		addressMap := getAddressSpaces(c, cloud.Name, id)
		if addressMap == nil {
			c.AbortWithStatusJSON(400, createErrorResponse(id, fmt.Sprintf("Failed to retrieve used address spaces for cloud %s", cloud.Name)))
			return 
		}
		for _, cloudRegion := range addressMap.Mappings {
			addressSpaceMap[cloud.Name + "\\" + cloudRegion.Region] = cloudRegion.AddressSpace
		}
	}
}

func getNewAddressSpace(c *gin.Context) string {
	highestBlockUsed := -1
	for _, address := range addressSpaceMap {
		fmt.Println(address)
		blockNumber, err := strconv.Atoi(strings.Split(address, ".")[1])
		if err != nil {
			c.AbortWithStatusJSON(400, createErrorResponse("", "Could not parse existing address spaces"))
			return ""
		}

		if blockNumber > highestBlockUsed {
			highestBlockUsed = blockNumber
		}
	}

	if highestBlockUsed >= 256 {
		c.AbortWithStatusJSON(400, createErrorResponse("", "Entire address space used"))
		return ""
	}

	return fmt.Sprintf("10.%d.0.0/16", highestBlockUsed + 1)
}

func resourceCreate(c *gin.Context) {
	// TODO: provide address space (if needed)
	id := c.Param("id")
	cloud := c.Param("cloud")
	cloudClient, ok := pluginAddresses[cloud]
	if !ok {
		c.AbortWithStatusJSON(400, createErrorResponse(id, "Invalid cloud name"))
		return
	}

	var resourceWithString invisinetspb.ResourceDescriptionString

	if err := c.BindJSON(&resourceWithString); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return
	}

	// Check the resource region and get corresponding address space from it (or )
	updateAddressSpaceMap(c, "")
	region := c.Param("region")
	addressSpace, ok := addressSpaceMap[region]
	if !ok {
		// Create a new address space 
		addressSpace = getNewAddressSpace(c)
	}

	resource :=  invisinetspb.ResourceDescription{Id: resourceWithString.Id, Description: []byte(resourceWithString.Description), AddressSpace: addressSpace}

	conn, err := grpc.Dial(cloudClient, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return
	}

	client := invisinetspb.NewCloudPluginClient(conn)

	response, err := client.CreateResource(context.Background(), &resource)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
	}

	defer conn.Close()

	c.JSON(http.StatusOK, gin.H{
		"id":       id,
		"response": response.Message,
		"addressSpace": addressSpace,
	})
}

func main() {

	f, err := os.Open("config.yml")
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
	config = cfg

	for _, c := range config.Clouds {
		pluginAddresses[c.Name] = c.Host + ":" + c.Port
	}

	router := gin.Default()
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})

	router.GET("/cloud/:cloud/resources/:id/permit-list", permitListGet)
	router.POST("/cloud/:cloud/resources/:id/permit-list/rules", permitListRulesAdd)
	router.DELETE("/cloud/:cloud/resources/:id/permit-list/rules", permitListRulesDelete)
	router.POST("/cloud/:cloud/region/:region/resources/:id/", resourceCreate)
  
	err = router.Run(config.Server.Host + ":" + config.Server.Port)
	if err != nil {
		fmt.Println(err.Error())
	}
}
