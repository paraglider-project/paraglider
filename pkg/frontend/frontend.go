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

// TODO:
// Refactor to just a function that gives you a client to the plugin
// Unsubscribe on last tag reference delete --> how?
// When tag membership changes, automatically call a re-resolve permit list at those URIs that are subscribed (call GET on their permit list and then call AddRules)

package frontend

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
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

type Warning struct {
	Message string
}

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

// Returns whether the string provided is a valid IP/CIDR
func isIpAddrOrCidr(value string) bool {
	if strings.Contains(value, "/") {
		_, err := netip.ParsePrefix(value)
		if err != nil {
			return false
		}
		return true
	} else {
		_, err := netip.ParseAddr(value)
		if err != nil {
			return false
		}
		return true
	}
}

// Retrieve the IPs from a list of name mappings
func getIPsFromResolvedTag(mappings []*tagservicepb.NameMapping) []string {
	var ips []string
	for _, mapping := range mappings {
		ips = append(ips, mapping.Ip)
	}
	return ips
}

func checkAndCleanRule(rule *invisinetspb.PermitListRule) (*invisinetspb.PermitListRule, *Warning, error) {
	if len(rule.Tags) == 0 {
		return nil, nil, fmt.Errorf("Rule %s contains no tags", rule.Id)
	}
	if len(rule.Targets) != 0 {
		rule.Targets = []string{}
		return rule, &Warning{Message:fmt.Sprintf("Warning: targets for rule %s ignored", rule.Id)}, nil
	}
	return rule, nil, nil 
}

func createSubscriberName(cloud string, uri string) string {
	return cloud+">"+uri
}

func parseSubscriberName(sub string) (string, string) {
	// TODO: add if contains ","
	tokens := strings.Split(sub, ">")
	return tokens[0], tokens[1]
}

// Takes a set of permit list rules and returns the same list with all tags referenced in the original rules resolved to IPs
func (s *ControllerServer) resolvePermitListRules(list *invisinetspb.PermitList, subscribe bool, cloud string) (*invisinetspb.PermitList, error){
	for _, rule := range list.Rules {
		// Check rule validity and clean fields
		rule, _, err := checkAndCleanRule(rule) // TODO: use the warning
		if err != nil {
			return nil, fmt.Errorf("Invalid rule: %s", err.Error())
		}

		for _, tag := range rule.Tags {
			if !isIpAddrOrCidr(tag) {
				conn, err := grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					return nil, fmt.Errorf("Could not contact tag server: %s", err.Error())
				}
				defer conn.Close()
				
				// Send RPC to resolve tag
				client := tagservicepb.NewTagServiceClient(conn)
				resolvedTag, err := client.ResolveTag(context.Background(), &tagservicepb.Tag{TagName: tag})
				if err != nil {
					return nil, fmt.Errorf("Could not resolve tag: %s", err.Error())
				}

				// Subscribe self to tag
				if subscribe {
					_, err := client.Subscribe(context.Background(), 
											   &tagservicepb.Subscription{TagName: tag, 
													Subscriber: createSubscriberName(cloud, list.AssociatedResource)})
					if err != nil {
						return nil, fmt.Errorf("Could not subscribe to tag: %s", err.Error())
					}
				}

				rule.Targets = append(rule.Targets, getIPsFromResolvedTag(resolvedTag.Mappings)...)
			} else {
				rule.Targets = append(rule.Targets, tag)
			}
		}
	}
	return list, nil
}

func (s *ControllerServer) _permitListGet(c *gin.Context, pluginAddress string, id string) (*invisinetspb.PermitList, error) {
	// Connect to the cloud plugin
	conn, err := grpc.Dial(pluginAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send the GetPermitList RPC
	client := invisinetspb.NewCloudPluginClient(conn)
	emptyresourceId := invisinetspb.ResourceID{Id: id}

	response, err := client.GetPermitList(context.Background(), &emptyresourceId)
	if err != nil {
		return nil, err
	}

	return response, nil
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

	response, err := s._permitListGet(c, cloudClient, id)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":              id,
		"permitlist":      response,
	})
}

func (s *ControllerServer) _permitListRulesAdd(c *gin.Context, pluginAddress string, permitList *invisinetspb.PermitList, cloud string) (*invisinetspb.BasicResponse, error) {
	// Resolve tags referenced in rules 
	permitList, err := s.resolvePermitListRules(permitList, true, cloud)
	if err != nil {
		return nil, err
	}

	// Create connection to cloud plugin
	conn, err := grpc.Dial(pluginAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send RPC to create rules
	client := invisinetspb.NewCloudPluginClient(conn)
	response, err := client.AddPermitListRules(context.Background(), permitList)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
	}

	return response, nil
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
	var permitListRules *invisinetspb.PermitList
	if err := c.BindJSON(&permitListRules); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	response, err := s._permitListRulesAdd(c, cloudClient, permitListRules, cloud)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
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

	// TODO: Resolve tags (for correct lookup in cloud plugin) and unsubscribe
	// Resolve tags referenced in rules 
	s.resolvePermitListRules(&permitListRules, false, cloud)
	// could have the RPC return that info and then act on that --> yeah, let's do that

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

// Get tag from local tag service
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

	c.JSON(http.StatusOK, response)
}

// Resolve tag down to IP/URI(s) from local tag service
func (s *ControllerServer) resolveTag(c *gin.Context) {
	// Call resolveTag locally
	conn, err := grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()
	
	// Send RPC to get tag
	tag := c.Param("tag")
	client := tagservicepb.NewTagServiceClient(conn)
	response, err := client.ResolveTag(context.Background(), &tagservicepb.Tag{TagName: tag})
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
	}

	c.JSON(http.StatusOK, response)
}

func clearRuleTargets(rules *invisinetspb.PermitList) *invisinetspb.PermitList {
	for _, rule := range rules.Rules {
		rule.Targets = []string{}
	}
	return rules
}

func (s *ControllerServer) updateSubscribers(c *gin.Context, tag string) {
	// Get Subscribers from tag service for tag
	// For each subscriber, 
		// Call GetPermitList
		// Then call SetPermitList with resolved rules (note: create helper functions without the network stuff for these functions so they can be reusable)
	conn, err := grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()

	client := tagservicepb.NewTagServiceClient(conn)
	response, err := client.GetSubscribers(context.Background(), &tagservicepb.Tag{TagName: tag})
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	for _, subscriber := range response.Subscribers {
		cloud, uri := parseSubscriberName(subscriber)
		cloudClient, ok := s.pluginAddresses[cloud]
		if !ok {
			c.AbortWithStatusJSON(400, createErrorResponse("Invalid cloud name for tag subscriber")) // TODO: Add more
			return
		}

		permitList, err := s._permitListGet(c, cloudClient, uri)
		if err != nil {
			c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
			return
		}

		permitList = clearRuleTargets(permitList)

		_, err = s._permitListRulesAdd(c, cloudClient, permitList, cloud)
		if err != nil {
			c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
			return
		}
	}
}

// Set tag mapping in local db 
func (s *ControllerServer) setTag(c *gin.Context) {
	parentTag := c.Param("tag")
	var childTags []string
	if err := c.BindJSON(&childTags); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	tagMapping := &tagservicepb.TagMapping{ParentTag: parentTag, ChildTags: childTags}

	// Call SetTag
	conn, err := grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()

	client := tagservicepb.NewTagServiceClient(conn)
	response, err := client.SetTag(context.Background(), tagMapping)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	 
	// Look up subscribers and re-resolve the tag
	s.updateSubscribers(c, tagMapping.ParentTag)

	c.JSON(http.StatusOK, gin.H{
		"response": response.Message,
	})
}

// Set tag name in local db
func (s *ControllerServer) setName(c *gin.Context) {
	tagName := c.Param("tag")

	// Parse data
	var nameMapping tagservicepb.NameMapping
	if err := c.BindJSON(&nameMapping); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	nameMapping.TagName = tagName

	// Call SetName
	conn, err := grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()

	client := tagservicepb.NewTagServiceClient(conn)
	response, err := client.SetName(context.Background(), &nameMapping)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"response": response.Message,
	})
}

// Delete tag (all mappings under it) in local db
func (s *ControllerServer) deleteTag(c *gin.Context) {
	tagName := c.Param("tag")
	tag := &tagservicepb.Tag{TagName: tagName}

	// Call DeleteTag
	conn, err := grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()

	client := tagservicepb.NewTagServiceClient(conn)
	response, err := client.DeleteTag(context.Background(), tag)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Look up subscribers and re-resolve the tags
	// Note that deleting the tag does not remove it from the list, but it does resolve to nothing
	s.updateSubscribers(c, tag.TagName)

	c.JSON(http.StatusOK, gin.H{
		"response": response.Message,
	})
}

// Delete members of tag in local db and in each cloud (if implemented/supported)
func (s *ControllerServer) deleteTagMember(c *gin.Context) {
	parentTag := c.Param("tag")
	var childTags []string
	if err := c.BindJSON(&childTags); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	tagMapping := &tagservicepb.TagMapping{ParentTag: parentTag, ChildTags: childTags}

	// Call DeleteTagMember
	conn, err := grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()

	client := tagservicepb.NewTagServiceClient(conn)
	response, err := client.DeleteTagMember(context.Background(), tagMapping)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Look up subscribers and re-resolve the tag
	s.updateSubscribers(c, tagMapping.ParentTag)
	
	c.JSON(http.StatusOK, gin.H{
		"response": response.Message,
	})
}

// Delete tag name in local db
func (s *ControllerServer) deleteName(c *gin.Context) {
	tagName := c.Param("tag")

	// Call DeleteName
	conn, err := grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()

	client := tagservicepb.NewTagServiceClient(conn)
	response, err := client.DeleteName(context.Background(), &tagservicepb.Tag{TagName: tagName})
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
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
	router.GET("/tags/:tag/resolve", server.resolveTag)
	router.POST("/tags/:tag", server.setTag)
	router.POST("/tags/:tag/name", server.setName)
	router.DELETE("/tags/:tag", server.deleteTag)
	router.DELETE("/tags/:tag/members/", server.deleteTagMember)
	router.DELETE("/tags/:tag/name", server.deleteName)
	
	// Run server
	err = router.Run(server.config.Server.Host + ":" + server.config.Server.Port)
	if err != nil {
		fmt.Println(err.Error())
	}
}
