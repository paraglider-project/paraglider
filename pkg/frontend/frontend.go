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
	tagservicepb "github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
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

	TagService struct {
		Port string `yaml:"port"`
		Host string `yaml:"host"`
	} `yaml:"tagService"`

	Clouds []Cloud `yaml:"cloudPlugins"`
}

type ControllerServer struct {
	invisinetspb.UnimplementedControllerServer
	pluginAddresses   map[string]string
	usedAddressSpaces map[string][]string
	localTagService   string
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

	newAddressSpace := &invisinetspb.AddressSpace{Address: fmt.Sprintf("10.%d.0.0/16", highestBlockUsed+1)}
	return newAddressSpace, nil
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

func (s *ControllerServer) getTag(c *gin.Context) {
	// Call getTag locally
	conn, err := grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()
	
	// Send RPC to get tag
	tag := c.Param("tag")
	client := tagservicepb.NewTagServiceClient(conn)
	response, err := client.GetTag(context.Background(), &tagservicepb.Tag{TagName: tag})
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
	}

	c.JSON(http.StatusOK, gin.H{
		"parent_tag":    response.ParentTag,
		"child_tags":    response.ChildTags,
	})
}

func (s *ControllerServer) setTag(c *gin.Context) {
	parentTag := c.Param("tag")
	var childTags []string
	if err := c.BindJSON(&childTags); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	tagMapping := &tagservicepb.TagMapping{ParentTag: parentTag, ChildTags: childTags}

	// Call SetTag locally
	conn, err := grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	client := tagservicepb.NewTagServiceClient(conn)
	response, err := client.SetTag(context.Background(), tagMapping)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	localResult := response.Message
	conn.Close()

	// Call SetTag for each cloud plugin
	results := make(map[string]string)
	for cloud, addr := range s.pluginAddresses {
		conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			results[cloud] = err.Error()
			continue
		}

		client := tagservicepb.NewTagServiceClient(conn)
		response, err := client.SetTag(context.Background(), tagMapping)
		if err != nil {
			results[cloud] = err.Error()
			continue
		}

		results[cloud] = response.Message
		conn.Close()
	}

	results["LocalTagService"] = localResult
	c.JSON(http.StatusOK, results)
}

func (s *ControllerServer) deleteTag(c *gin.Context) {
	tagName := c.Param("tag")
	tag := &tagservicepb.Tag{TagName: tagName}

	// Call DeleteTag locally
	conn, err := grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	client := tagservicepb.NewTagServiceClient(conn)
	response, err := client.DeleteTag(context.Background(), tag)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	localResult := response.Message
	conn.Close()

	// Call DeleteTag for each cloud plugin
	results := make(map[string]string)
	for cloud, addr := range s.pluginAddresses {
		conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			results[cloud] = err.Error()
			continue
		}

		client := tagservicepb.NewTagServiceClient(conn)
		response, err := client.DeleteTag(context.Background(), tag)
		if err != nil {
			results[cloud] = err.Error()
			continue
		}

		results[cloud] = response.Message
		conn.Close()
	}

	results["LocalTagService"] = localResult
	c.JSON(http.StatusOK, results)
}

func (s *ControllerServer) deleteTagMember(c *gin.Context) {
	parentTag := c.Param("tag")
	var childTags []string
	if err := c.BindJSON(&childTags); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	tagMapping := &tagservicepb.TagMapping{ParentTag: parentTag, ChildTags: childTags}

	// Call DeleteTagMember locally
	conn, err := grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	client := tagservicepb.NewTagServiceClient(conn)
	response, err := client.DeleteTagMember(context.Background(), tagMapping)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	localResult := response.Message
	conn.Close()

	// Call DeleteTag for each cloud plugin
	results := make(map[string]string)
	for cloud, addr := range s.pluginAddresses {
		conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			results[cloud] = err.Error()
			continue
		}

		client := tagservicepb.NewTagServiceClient(conn)
		response, err := client.DeleteTagMember(context.Background(), tagMapping)
		if err != nil {
			results[cloud] = err.Error()
			continue
		}

		results[cloud] = response.Message
		conn.Close()
	}

	results["LocalTagService"] = localResult
	c.JSON(http.StatusOK, results)
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
	server.localTagService = cfg.TagService.Host + ":" + cfg.TagService.Port

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
	router.GET("/tags/:tag", server.getTag)
	router.POST("/tags/:tag", server.setTag)
	router.DELETE("/tags/:tag", server.deleteTag)
	router.DELETE("/tags/:tag/members/", server.deleteTagMember)
	
	// Run server
	err = router.Run(server.config.Server.Host + ":" + server.config.Server.Port)
	if err != nil {
		fmt.Println(err.Error())
	}
}
