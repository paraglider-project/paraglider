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

package orchestrator

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/gin-gonic/gin"

	grpc "google.golang.org/grpc"
	insecure "google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/NetSys/invisinets/pkg/kv_store/storepb"
	config "github.com/NetSys/invisinets/pkg/orchestrator/config"
	tagservicepb "github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
	utils "github.com/NetSys/invisinets/pkg/utils"
)

const (
	GetPermitListRulesURL    string = "/namespaces/:namespace/clouds/:cloud/resources/:resourceName/rules"
	PermitListRulePOSTURL    string = "/namespaces/:namespace/clouds/:cloud/resources/:resourceName/rules"
	PermitListRulePUTURL     string = "/namespaces/:namespace/clouds/:cloud/resources/:resourceName/rules/:ruleName"
	AddPermitListRulesURL    string = "/namespaces/:namespace/clouds/:cloud/resources/:resourceName/applyRules"
	DeletePermitListRulesURL string = "/namespaces/:namespace/clouds/:cloud/resources/:resourceName/deleteRules"
	CreateResourcePUTURL     string = "/namespaces/:namespace/clouds/:cloud/resources/:resourceName"
	CreateResourcePOSTURL    string = "/namespaces/:namespace/clouds/:cloud/resources"
	GetTagURL                string = "/tags/:tag"
	ResolveTagURL            string = "/tags/:tag/resolveMembers"
	SetTagURL                string = "/tags/:tag/applyMembers"
	DeleteTagURL             string = "/tags/:tag"
	DeleteTagMemberURL       string = "/tags/:tag/members/:member"
	ListNamespacesURL        string = "/namespaces"
)

type Warning struct {
	Message string
}

type ControllerServer struct {
	invisinetspb.UnimplementedControllerServer
	pluginAddresses           map[string]string
	usedAddressSpaces         []*invisinetspb.AddressSpaceMapping
	usedAsns                  []uint32
	usedBgpPeeringIpAddresses map[string][]string
	localTagService           string
	localKVStoreService       string
	config                    config.Config
	namespace                 string
}

type ResourceInfo struct {
	name      string
	uri       string
	cloud     string
	namespace string
}

// Return a string usable with Sprintf for inserting URL params
func GetFormatterString(url string) string {
	new_tokens := []string{}
	for _, token := range strings.Split(string(url), "/") {
		if strings.Contains(token, ":") || strings.Contains(token, "*") {
			new_tokens = append(new_tokens, "%s")
		} else {
			new_tokens = append(new_tokens, token)
		}
	}
	return strings.Join(new_tokens, "/")
}

func createErrorResponse(message string) gin.H {
	return gin.H{"error": message}
}

// Returns whether the string provided is a valid IP/CIDR
func isIpAddrOrCidr(value string) bool {
	if strings.Contains(value, "/") {
		_, err := netip.ParsePrefix(value)
		return err == nil
	} else {
		_, err := netip.ParseAddr(value)
		return err == nil
	}
}

// Retrieve the IPs from a list of name mappings
func getIPsFromResolvedTag(mappings []*tagservicepb.TagMapping) []string {
	ips := make([]string, len(mappings))
	for i, mapping := range mappings {
		ips[i] = *mapping.Ip
	}
	return ips
}

// Check if rules given by the user have tags (requirement) and remove any targets they contain (should only be written by the controller)
func checkAndCleanRule(rule *invisinetspb.PermitListRule) (*invisinetspb.PermitListRule, *Warning, error) {
	if len(rule.Tags) == 0 {
		return nil, nil, fmt.Errorf("rule %s contains no tags", rule.Id)
	}
	if len(rule.Targets) != 0 {
		rule.Targets = []string{}
		return rule, &Warning{Message: fmt.Sprintf("Warning: targets for rule %s ignored", rule.Id)}, nil
	}
	return rule, nil, nil
}

// Format a subscriber name so that when the value is looked up, it is clear which cloud and namespace the URI belongs to
func createSubscriberName(namespace string, cloud string, uri string) string {
	return namespace + ">" + cloud + ">" + uri
}

// Parse subscriber names from database to get the namespace, cloud and URI
func parseSubscriberName(sub string) (string, string, string) {
	if strings.Contains(sub, ">") {
		tokens := strings.Split(sub, ">")
		return tokens[0], tokens[1], tokens[2]
	}
	return sub, "", ""
}

func createTagName(namespace string, cloud string, tag string) string {
	return namespace + "." + cloud + "." + tag
}

// Get the URI of a tag
func (s *ControllerServer) getTagUri(tag string) (string, error) {
	conn, err := grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return "", fmt.Errorf("could not contact tag server: %s", err.Error())
	}
	defer conn.Close()

	// Send RPC to get tag
	client := tagservicepb.NewTagServiceClient(conn)
	response, err := client.GetTag(context.Background(), &tagservicepb.Tag{TagName: tag})
	if err != nil {
		return "", fmt.Errorf("could not get tag: %s", err.Error())
	}

	if *response.Uri == "" {
		return "", fmt.Errorf("tag %s is not an individual resource tag", tag)
	}
	return *response.Uri, nil
}

// Get URL params for a resource and resolve the resource name if needed
func (s *ControllerServer) getAndValidateResourceURLParams(c *gin.Context, resolveTag bool) (*ResourceInfo, string, error) {
	tag := c.Param("resourceName")
	cloud := c.Param("cloud")
	namespace := c.Param("namespace")

	// Ensure correct cloud name
	cloudClient, ok := s.pluginAddresses[cloud]
	if !ok {
		return nil, "", fmt.Errorf("invalid cloud name: %s", cloud)
	}

	if resolveTag {
		uri, err := s.getTagUri(createTagName(namespace, cloud, tag))
		if err != nil {
			return nil, "", err
		}

		return &ResourceInfo{name: tag, uri: uri, namespace: namespace, cloud: cloud}, cloudClient, nil
	} else {
		return &ResourceInfo{name: tag, namespace: namespace, cloud: cloud}, cloudClient, nil
	}
}

// Takes a set of permit list rules and returns the same list with all tags referenced in the original rules resolved to IPs
func (s *ControllerServer) resolvePermitListRules(rules []*invisinetspb.PermitListRule, resource *ResourceInfo, subscribe bool) ([]*invisinetspb.PermitListRule, error) {
	for _, rule := range rules {
		// Check rule validity and clean fields
		rule, _, err := checkAndCleanRule(rule) // TODO @smcclure20: use the warning and report it to the user
		if err != nil {
			return nil, fmt.Errorf("invalid rule: %s", err.Error())
		}

		for _, tag := range rule.Tags {
			if !isIpAddrOrCidr(tag) {
				conn, err := grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					return nil, fmt.Errorf("could not contact tag server: %s", err.Error())
				}
				defer conn.Close()

				// Send RPC to resolve tag
				client := tagservicepb.NewTagServiceClient(conn)
				resolvedTag, err := client.ResolveTag(context.Background(), &tagservicepb.Tag{TagName: tag})
				if err != nil {
					return nil, fmt.Errorf("could not resolve tag: %s", err.Error())
				}

				// Subscribe self to tag
				if subscribe {
					_, err := client.Subscribe(context.Background(),
						&tagservicepb.Subscription{TagName: tag,
							Subscriber: createSubscriberName(resource.namespace, resource.cloud, resource.uri)})
					if err != nil {
						return nil, fmt.Errorf("could not subscribe to tag: %s", err.Error())
					}
				}

				rule.Targets = append(rule.Targets, getIPsFromResolvedTag(resolvedTag.Mappings)...)
			} else {
				rule.Targets = append(rule.Targets, tag)
			}
		}
	}
	return rules, nil
}

// Get permit list with ID from plugin
func (s *ControllerServer) _permitListGet(namespace string, resourceId string, pluginAddress string) (*invisinetspb.GetPermitListResponse, error) {
	// Connect to the cloud plugin
	conn, err := grpc.Dial(pluginAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send the GetPermitList RPC
	client := invisinetspb.NewCloudPluginClient(conn)
	emptyresourceId := invisinetspb.GetPermitListRequest{Resource: resourceId, Namespace: namespace}

	response, err := client.GetPermitList(context.Background(), &emptyresourceId)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Get specified PermitList from given cloud
func (s *ControllerServer) permitListGet(c *gin.Context) {
	resourceInfo, cloudClient, err := s.getAndValidateResourceURLParams(c, true)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	response, err := s._permitListGet(resourceInfo.namespace, resourceInfo.uri, cloudClient)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, response.Rules)
}

// Add rules to a resource specified in the permit list in the given cloud
func (s *ControllerServer) _permitListRulesAdd(req *invisinetspb.AddPermitListRulesRequest, resource *ResourceInfo, pluginAddress string) (*invisinetspb.AddPermitListRulesResponse, error) {
	// Resolve tags referenced in rules
	rules, err := s.resolvePermitListRules(req.Rules, resource, true)
	if err != nil {
		return nil, err
	}
	req.Rules = rules

	// Create connection to cloud plugin
	conn, err := grpc.Dial(pluginAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send RPC to create rules
	client := invisinetspb.NewCloudPluginClient(conn)
	response, err := client.AddPermitListRules(context.Background(), req)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Add permit list rules to specified resource
func (s *ControllerServer) permitListRulesBulkAdd(c *gin.Context) {
	resourceInfo, cloudClient, err := s.getAndValidateResourceURLParams(c, true)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Parse permit list rules to add
	var rules []*invisinetspb.PermitListRule
	if err := c.BindJSON(&rules); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	request := &invisinetspb.AddPermitListRulesRequest{Rules: rules, Namespace: resourceInfo.namespace, Resource: resourceInfo.uri}

	_, err = s._permitListRulesAdd(request, resourceInfo, cloudClient)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
}

// Add a single rule to a resource permit list
func (s *ControllerServer) permitListRuleAdd(c *gin.Context) {
	resourceInfo, cloudClient, err := s.getAndValidateResourceURLParams(c, true)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Parse permit list rules to add
	var rule *invisinetspb.PermitListRule
	if err := c.BindJSON(&rule); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	if c.Request.Method == "PUT" {
		// Get rule name from URL
		ruleName := c.Param("ruleName")
		if ruleName == "" {
			c.AbortWithStatusJSON(400, createErrorResponse("rule name not specified"))
			return
		}
		rule.Name = ruleName // Note: if the name is provided in the request body, it is just overwritten
	}

	request := &invisinetspb.AddPermitListRulesRequest{Rules: []*invisinetspb.PermitListRule{rule}, Namespace: resourceInfo.namespace, Resource: resourceInfo.uri}

	_, err = s._permitListRulesAdd(request, resourceInfo, cloudClient)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
}

// Find the tags dereferenced between two versions of a permit list
func diffTagReferences(beforeList []*invisinetspb.PermitListRule, afterList []*invisinetspb.PermitListRule) []string {
	beforeListSet := make(map[string]bool)
	afterListSet := make(map[string]bool)
	tagsDereferenced := []string{}

	for _, rule := range beforeList {
		for _, tag := range rule.Tags {
			if !isIpAddrOrCidr(tag) {
				beforeListSet[tag] = true
			}
		}
	}

	for _, rule := range afterList {
		for _, tag := range rule.Tags {
			if !isIpAddrOrCidr(tag) {
				afterListSet[tag] = true
			}
		}
	}

	// Find tags no longer referenced after the change
	for tag := range beforeListSet {
		if _, ok := afterListSet[tag]; !ok {
			tagsDereferenced = append(tagsDereferenced, tag)
		}
	}

	return tagsDereferenced
}

// Check whether any tags have been dereferenced by the permit list and unsubscribe from any that have
func (s *ControllerServer) checkAndUnsubscribe(resource *ResourceInfo, beforeList []*invisinetspb.PermitListRule, afterList []*invisinetspb.PermitListRule) error {
	// Find the dereferenced tags
	tagsToUnsubscribe := diffTagReferences(beforeList, afterList)

	// If none dereferenced, return early
	if len(tagsToUnsubscribe) == 0 {
		return nil
	}

	// Dial the tag service
	conn, err := grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	client := tagservicepb.NewTagServiceClient(conn)

	// Send RPC to unsubscribe from each tag
	for _, tag := range tagsToUnsubscribe {
		_, err := client.Unsubscribe(context.Background(), &tagservicepb.Subscription{TagName: tag, Subscriber: createSubscriberName(resource.namespace, resource.cloud, resource.uri)})
		if err != nil {
			return err
		}
	}

	return nil
}

// Delete permit list rules to specified resource
func (s *ControllerServer) permitListRulesDelete(c *gin.Context) {
	resourceInfo, cloudClient, err := s.getAndValidateResourceURLParams(c, true)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Parse rules to delete
	var ruleNames []string
	if err := c.BindJSON(&ruleNames); err != nil {
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
	client := invisinetspb.NewCloudPluginClient(conn)

	// First, get the original list
	permitListBefore, err := client.GetPermitList(context.Background(), &invisinetspb.GetPermitListRequest{Resource: resourceInfo.uri, Namespace: resourceInfo.namespace})
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Send RPC to delete the rules
	request := &invisinetspb.DeletePermitListRulesRequest{RuleNames: ruleNames, Namespace: resourceInfo.namespace, Resource: resourceInfo.uri}
	_, err = client.DeletePermitListRules(context.Background(), request)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Then get the final list to tell which tags should be unsubscribed
	permitListAfter, err := client.GetPermitList(context.Background(), &invisinetspb.GetPermitListRequest{Resource: resourceInfo.uri, Namespace: resourceInfo.namespace})
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Determine which tags have been dereferenced from the permit list and unsubscribe
	// TODO @smcclure20: Have to do a permit list diff since there is no reverse lookup to see which tags a URI is subscribed to.
	// 					 Supporting this will probably require a database migration (non-KV store)
	if err := s.checkAndUnsubscribe(resourceInfo, permitListBefore.Rules, permitListAfter.Rules); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
}

// Delete a single rule from a resource permit list
func (s *ControllerServer) permitListRuleDelete(c *gin.Context) {
	resourceInfo, cloudClient, err := s.getAndValidateResourceURLParams(c, true)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Get rule name from URL
	ruleName := c.Param("ruleName")
	if ruleName == "" {
		c.AbortWithStatusJSON(400, createErrorResponse("rule name not specified"))
		return
	}

	// Create connection to cloud plugin
	conn, err := grpc.Dial(cloudClient, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()
	client := invisinetspb.NewCloudPluginClient(conn)

	// First, get the original list
	permitListBefore, err := client.GetPermitList(context.Background(), &invisinetspb.GetPermitListRequest{Resource: resourceInfo.uri, Namespace: resourceInfo.namespace})
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Send RPC to delete the rules
	request := &invisinetspb.DeletePermitListRulesRequest{RuleNames: []string{ruleName}, Namespace: resourceInfo.namespace, Resource: resourceInfo.uri}
	_, err = client.DeletePermitListRules(context.Background(), request)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Then get the final list to tell which tags should be unsubscribed
	permitListAfter, err := client.GetPermitList(context.Background(), &invisinetspb.GetPermitListRequest{Resource: resourceInfo.uri, Namespace: resourceInfo.namespace})
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Determine which tags have been dereferenced from the permit list and unsubscribe
	// TODO @smcclure20: Have to do a permit list diff since there is no reverse lookup to see which tags a URI is subscribed to.
	// 					 Supporting this will probably require a database migration (non-KV store)
	if err := s.checkAndUnsubscribe(resourceInfo, permitListBefore.Rules, permitListAfter.Rules); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
}

// Get used address spaces from a specified cloud
func (s *ControllerServer) getAddressSpaces(cloud string) ([]*invisinetspb.AddressSpaceMapping, error) {
	// Ensure correct cloud name
	cloudClient, ok := s.pluginAddresses[cloud]
	if !ok {
		return nil, errors.New("invalid cloud name")
	}

	// Connect to cloud plugin
	conn, err := grpc.Dial(cloudClient, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("unable to connect to cloud plugin: %s", err.Error())
	}
	defer conn.Close()

	// Send the RPC to get the address spaces
	client := invisinetspb.NewCloudPluginClient(conn)
	req := &invisinetspb.GetUsedAddressSpacesRequest{Deployments: s.getInvisinetsDeployments(cloud)}
	resp, err := client.GetUsedAddressSpaces(context.Background(), req)

	return resp.AddressSpaceMappings, err
}

// Update local address space map by getting used address spaces from each cloud plugin
func (s *ControllerServer) updateUsedAddressSpaces() error {
	// Call each cloud to get address spaces used
	for _, cloud := range s.config.CloudPlugins {
		addressSpaceMappings, err := s.getAddressSpaces(cloud.Name)
		if err != nil {
			return fmt.Errorf("could not retrieve address spaces for cloud %s (error: %s)", cloud, err.Error())
		}
		s.usedAddressSpaces = append(s.usedAddressSpaces, addressSpaceMappings...)
	}
	return nil
}

// Get a new address block for a new virtual network
// TODO @smcclure20: Later, this should allocate more efficiently and with different size address blocks (eg, GCP needs larger than Azure since a VPC will span all regions)
func (s *ControllerServer) FindUnusedAddressSpace(c context.Context, _ *invisinetspb.FindUnusedAddressSpaceRequest) (*invisinetspb.FindUnusedAddressSpaceResponse, error) {
	err := s.updateUsedAddressSpaces()
	if err != nil {
		return nil, err
	}
	highestBlockUsed := -1
	for _, addressSpaceMapping := range s.usedAddressSpaces {
		for _, address := range addressSpaceMapping.AddressSpaces {
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
		return nil, errors.New("all address blocks used")
	}

	newAddressSpace := &invisinetspb.FindUnusedAddressSpaceResponse{AddressSpace: fmt.Sprintf("10.%d.0.0/16", highestBlockUsed+1)}
	return newAddressSpace, nil
}

// Gets unused address spaces across all clouds
func (s *ControllerServer) GetUsedAddressSpaces(c context.Context, _ *invisinetspb.Empty) (*invisinetspb.GetUsedAddressSpacesResponse, error) {
	err := s.updateUsedAddressSpaces()
	if err != nil {
		return nil, err
	}
	// Fill in deployment fields since the cloud plugins don't do that
	for _, addressSpace := range s.usedAddressSpaces {
		addressSpace.Deployment = proto.String(s.getCloudDeployment(addressSpace.Cloud, addressSpace.Namespace))
	}
	return &invisinetspb.GetUsedAddressSpacesResponse{AddressSpaceMappings: s.usedAddressSpaces}, nil
}

// Get used ASNs from a specified cloud
func (s *ControllerServer) getUsedAsns(cloud string) (*invisinetspb.GetUsedAsnsResponse, error) {
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

	// Send the RPC to get the ASNs
	client := invisinetspb.NewCloudPluginClient(conn)
	req := &invisinetspb.GetUsedAsnsRequest{Deployments: s.getInvisinetsDeployments(cloud)}
	resp, err := client.GetUsedAsns(context.Background(), req)

	return resp, err
}

func (s *ControllerServer) updateUsedAsns() error {
	for _, cloud := range s.config.CloudPlugins {
		asnList, err := s.getUsedAsns(cloud.Name)
		if err != nil {
			return fmt.Errorf("Could not retrieve address spaces for cloud %s (error: %s)", cloud, err.Error())
		}
		s.usedAsns = append(s.usedAsns, asnList.Asns...)
	}
	return nil
}

func (s *ControllerServer) FindUnusedAsn(c context.Context, _ *invisinetspb.FindUnusedAsnRequest) (*invisinetspb.FindUnusedAsnResponse, error) {
	err := s.updateUsedAsns()
	if err != nil {
		return nil, fmt.Errorf("unable to update used asns: %w", err)
	}

	usedAsns := make(map[uint32]bool)
	for _, asn := range s.usedAsns {
		usedAsns[asn] = true
	}

	// Find smallest unused ASN
	var unusedAsn uint32 = 0
	var i uint32
	// 2-byte ASNs
	for i = MIN_PRIVATE_ASN_2BYTE; i <= MAX_PRIVATE_ASN_2BYTE; i++ {
		if !usedAsns[i] {
			unusedAsn = i
			break
		}
	}
	if unusedAsn == 0 {
		// 4-byte ASNs
		for i = MIN_PRIVATE_ASN_4BYTE; i <= MAX_PRIVATE_ASN_4BYTE; i++ {
			if !usedAsns[i] {
				unusedAsn = i
				break
			}
		}
		if unusedAsn == 0 {
			return nil, fmt.Errorf("all private ASNs have been used")
		}
	}

	resp := &invisinetspb.FindUnusedAsnResponse{Asn: unusedAsn}
	return resp, nil
}

// Get used BGP peering IP addresses from a specified cloud
func (s *ControllerServer) getUsedBgpPeeringIpAddresses(cloud string) (*invisinetspb.GetUsedBgpPeeringIpAddressesResponse, error) {
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

	// Send the RPC to get the BGP peering IP addresses
	client := invisinetspb.NewCloudPluginClient(conn)
	req := &invisinetspb.GetUsedBgpPeeringIpAddressesRequest{Deployments: s.getInvisinetsDeployments(cloud)}
	resp, err := client.GetUsedBgpPeeringIpAddresses(context.Background(), req)

	return resp, err
}

func (s *ControllerServer) updateUsedBgpPeeringIpAddresses(namespace string) error {
	for _, cloud := range s.config.CloudPlugins {
		bgpPeeringIpAddressesList, err := s.getUsedBgpPeeringIpAddresses(cloud.Name)
		if err != nil {
			return fmt.Errorf("Could not retrieve address spaces for cloud %s (error: %s)", cloud, err.Error())
		}
		s.usedBgpPeeringIpAddresses[cloud.Name] = bgpPeeringIpAddressesList.IpAddresses
	}
	return nil
}

// Not a public RPC (hence private) used by cloud plugins but follows the same pattern as FindUnusedAsn
func (s *ControllerServer) findUnusedBgpPeeringIpAddresses(ctx context.Context, cloud1 string, cloud2 string, namespace string) ([]string, error) {
	// Retrieve all used peering IPs from all clouds
	err := s.updateUsedBgpPeeringIpAddresses(namespace)
	if err != nil {
		return nil, fmt.Errorf("unable to update used BGP peering IP addresses: %w", err)
	}

	// Compile used ips into a map
	usedBgpPeeringIpAddresses := make(map[string]bool)
	for _, cloudBgpPeeringIpAddresses := range s.usedBgpPeeringIpAddresses {
		for _, ipAddressString := range cloudBgpPeeringIpAddresses {
			ipAddress, err := netip.ParseAddr(ipAddressString)
			if err != nil {
				return nil, fmt.Errorf("unable to parse BGP peering IP addresses")
			}
			usedBgpPeeringIpAddresses[ipAddress.String()] = true
		}
	}

	// Set the minimum and maximum based on APIPA ranges (RFC 3927)
	// Each min and max are set to the first usable IP address in the /30 subnet (e.g., 169.254.0.1 is the first usable IP address in 169.254.0.0/30)
	var minIp, maxIp netip.Addr
	if cloud1 == utils.AZURE || cloud2 == utils.AZURE {
		// Azure has a more restrictive APIPA range
		minIp = netip.MustParseAddr("169.254.21.1")
		maxIp = netip.MustParseAddr("169.254.22.253")
	} else {
		minIp = netip.MustParseAddr("169.254.0.1")
		maxIp = netip.MustParseAddr("169.254.255.253")
	}

	// Calculate how many subnets are required
	requiredIps := utils.GetNumVpnConnections(cloud1, cloud2) * 2 // Each VPN connection requires two IP addresses (one for each cloud)
	ips := make([]string, requiredIps)

	// Find unused subnets
	i := 0
	ip := minIp
	for ip.Compare(maxIp) <= 0 {
		if err != nil {
			return nil, fmt.Errorf("unable to parse into prefix")
		}
		// We don't need to check if both IPs in the /30 subnet are used (i.e., 169.254.21.1 being used implies 169.254.21.2 is also being used)
		if !usedBgpPeeringIpAddresses[ip.String()] {
			ips[i] = ip.String()
			ips[i+1] = ip.Next().String()
			i += 2
			if i == requiredIps {
				break
			}
		}
		// Move to the next /30 subnet by incrementing four times
		for i := 0; i < 4; i++ {
			ip = ip.Next()
		}
	}
	if i < requiredIps {
		return nil, fmt.Errorf("unable to find the necessary number of unused subnets")
	}

	return ips, nil
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
func (s *ControllerServer) getCloudDeployment(cloud, namespace string) string {
	for ns, deployments := range s.config.Namespaces {
		if ns == namespace {
			for _, deployment := range deployments {
				if deployment.Name == cloud {
					return deployment.Deployment
				}
			}
		}
	}
	return ""
}

// Connects two clouds with VPN gateways
func (s *ControllerServer) ConnectClouds(ctx context.Context, req *invisinetspb.ConnectCloudsRequest) (*invisinetspb.BasicResponse, error) {
	if req.CloudA == req.CloudB {
		return nil, fmt.Errorf("must specify different clouds to connect")
	}

	// TODO @seankimkdy: cloudA and cloudB naming seems to be very prone to typos, so perhaps use another naming scheme[?
	if utils.MatchCloudProviders(req.CloudA, req.CloudB, utils.AZURE, utils.GCP) {
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
			return nil, fmt.Errorf("unable to connect to cloud plugin: %w", err)
		}
		defer cloudAConn.Close()
		cloudBClient := invisinetspb.NewCloudPluginClient(cloudBconn)

		ctx := context.Background()

		// Get BGP peering IP addresses
		bgpPeeringIpAddresses, err := s.findUnusedBgpPeeringIpAddresses(ctx, req.CloudA, req.CloudB, req.CloudANamespace)
		if err != nil {
			return nil, fmt.Errorf("unable to find unused bgp peering subnet")
		}
		cloudABgpPeeringIpAddresses := make([]string, len(bgpPeeringIpAddresses)/2)
		cloudBBgpPeeringIpAddresses := make([]string, len(bgpPeeringIpAddresses)/2)
		for i := 0; i < len(bgpPeeringIpAddresses)/2; i++ {
			cloudABgpPeeringIpAddresses[i] = bgpPeeringIpAddresses[i*2]
			cloudBBgpPeeringIpAddresses[i] = bgpPeeringIpAddresses[i*2+1]
		}

		cloudAInvisinetsDeployment := &invisinetspb.InvisinetsDeployment{Id: s.getCloudDeployment(req.CloudA, req.CloudANamespace), Namespace: req.CloudANamespace}
		cloudACreateVpnGatewayReq := &invisinetspb.CreateVpnGatewayRequest{
			Deployment:            cloudAInvisinetsDeployment,
			Cloud:                 req.CloudB,
			BgpPeeringIpAddresses: cloudABgpPeeringIpAddresses,
		}
		cloudACreateVpnGatewayResp, err := cloudAClient.CreateVpnGateway(ctx, cloudACreateVpnGatewayReq)
		if err != nil {
			return nil, fmt.Errorf("unable to create vpn gateway in cloud %s: %w", req.CloudA, err)
		}
		cloudBInvisinetsDeployment := &invisinetspb.InvisinetsDeployment{Id: s.getCloudDeployment(req.CloudB, req.CloudBNamespace), Namespace: req.CloudBNamespace}
		cloudBCreateVpnGatewayReq := &invisinetspb.CreateVpnGatewayRequest{
			Deployment:            cloudBInvisinetsDeployment,
			Cloud:                 req.CloudA,
			BgpPeeringIpAddresses: cloudBBgpPeeringIpAddresses,
		}
		cloudBCreateVpnGatewayResp, err := cloudBClient.CreateVpnGateway(ctx, cloudBCreateVpnGatewayReq)
		if err != nil {
			return nil, fmt.Errorf("unable to create vpn gateway in cloud %s: %w", req.CloudB, err)
		}

		sharedKey, err := generateSharedKey()
		if err != nil {
			return nil, fmt.Errorf("unable to generate shared key: %w", err)
		}

		cloudACreateVpnConnectionsReq := &invisinetspb.CreateVpnConnectionsRequest{
			Deployment:         cloudAInvisinetsDeployment,
			Cloud:              req.CloudB,
			Asn:                cloudBCreateVpnGatewayResp.Asn,
			GatewayIpAddresses: cloudBCreateVpnGatewayResp.GatewayIpAddresses,
			BgpIpAddresses:     cloudBBgpPeeringIpAddresses,
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
			GatewayIpAddresses: cloudACreateVpnGatewayResp.GatewayIpAddresses,
			BgpIpAddresses:     cloudABgpPeeringIpAddresses,
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

// Gets all deployments (in Invisinets) format for a given cloud
func (s *ControllerServer) getInvisinetsDeployments(cloud string) []*invisinetspb.InvisinetsDeployment {
	invDeployments := []*invisinetspb.InvisinetsDeployment{}
	for namespace, cloudDeployments := range s.config.Namespaces {
		for _, cloudDeployment := range cloudDeployments {
			if cloudDeployment.Name == cloud {
				invDeployments = append(invDeployments, &invisinetspb.InvisinetsDeployment{Id: cloudDeployment.Deployment, Namespace: namespace})
			}
		}
	}
	return invDeployments
}

// Create resource in specified cloud region
func (s *ControllerServer) resourceCreate(c *gin.Context) {
	resourceInfo, cloudClient, err := s.getAndValidateResourceURLParams(c, false)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Parse the resource description provided
	var resourceWithString invisinetspb.ResourceDescriptionString
	if err := c.BindJSON(&resourceWithString); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// If POST method, name not given in the URL, so get it from the request body
	if c.Request.Method == "POST" {
		resourceInfo.name = resourceWithString.Name
	}

	// Create connection to cloud plugin
	conn, err := grpc.Dial(cloudClient, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()

	// Send RPC to create the resource
	resource := invisinetspb.ResourceDescription{Id: resourceWithString.Id, Description: []byte(resourceWithString.Description), Namespace: resourceInfo.namespace}
	client := invisinetspb.NewCloudPluginClient(conn)
	resourceResp, err := client.CreateResource(context.Background(), &resource)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Automatically set tag (need the IP address, we have the name and URI)
	conn, err = grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()

	tagClient := tagservicepb.NewTagServiceClient(conn)
	_, err = tagClient.SetTag(context.Background(), &tagservicepb.TagMapping{TagName: createTagName(resourceInfo.namespace, resourceInfo.cloud, resourceInfo.name), Uri: &resourceResp.Uri, Ip: &resourceResp.Ip})
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error())) // TODO @smcclure20: change this to a warning?
		return
	}

	resourceResp.Name = resourceInfo.namespace + "." + resourceInfo.cloud + "." + resourceResp.Name

	c.JSON(http.StatusOK, resourceResp)
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

// Clear targets from rules provided by the user
func clearRuleTargets(rules []*invisinetspb.PermitListRule) []*invisinetspb.PermitListRule {
	for _, rule := range rules {
		rule.Targets = []string{}
	}
	return rules
}

// Update subscribers to a tag about membership changes
func (s *ControllerServer) updateSubscribers(tag string) error {
	// Get the subscribers to the tag
	conn, err := grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()

	client := tagservicepb.NewTagServiceClient(conn)
	response, err := client.GetSubscribers(context.Background(), &tagservicepb.Tag{TagName: tag})
	if err != nil {
		return err
	}

	// For each subscriber, get the current permit list, clear target fields, and re-apply the resolved rules
	for _, subscriber := range response.Subscribers {
		namespace, cloud, uri := parseSubscriberName(subscriber)
		cloudClient, ok := s.pluginAddresses[cloud]
		if !ok {
			return fmt.Errorf("invalid cloud name in subscriber name %s for tag %s", subscriber, tag)
		}

		getResp, err := s._permitListGet(namespace, uri, cloudClient)
		if err != nil {
			return err
		}

		rules := clearRuleTargets(getResp.Rules)

		addRequest := &invisinetspb.AddPermitListRulesRequest{Rules: rules, Namespace: namespace, Resource: uri}
		_, err = s._permitListRulesAdd(addRequest, &ResourceInfo{namespace: namespace, cloud: cloud, uri: uri}, cloudClient)
		if err != nil {
			return err
		}
	}

	return nil
}

// Set tag mapping in local db and update subscribers to membership change
func (s *ControllerServer) setTag(c *gin.Context) {
	// Parse data
	var tagMapping tagservicepb.TagMapping
	if err := c.BindJSON(&tagMapping); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Call SetTag
	conn, err := grpc.Dial(s.localTagService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()

	client := tagservicepb.NewTagServiceClient(conn)
	response, err := client.SetTag(context.Background(), &tagMapping)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Look up subscribers and re-resolve the tag
	if err := s.updateSubscribers(tagMapping.TagName); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"response": response.Message,
	})
}

// Delete tag (all mappings under it) in local db and update subscribers to membership change
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
	if err := s.updateSubscribers(tagName); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"response": response.Message,
	})
}

// Delete members of tag in local db and update subscribers to membership change
func (s *ControllerServer) deleteTagMember(c *gin.Context) {
	parentTag := c.Param("tag")
	memberTag := c.Param("member")
	tagMapping := &tagservicepb.TagMapping{TagName: parentTag, ChildTags: []string{memberTag}}

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
	if err := s.updateSubscribers(tagMapping.TagName); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"response": response.Message,
	})
}

// List all configured namespaces
func (s *ControllerServer) listNamespaces(c *gin.Context) {
	c.JSON(http.StatusOK, s.config.Namespaces)
}

// Get a value from the KV store
func (s *ControllerServer) GetValue(c context.Context, req *invisinetspb.GetValueRequest) (*invisinetspb.GetValueResponse, error) {
	conn, err := grpc.Dial(s.localKVStoreService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := storepb.NewKVStoreClient(conn)
	response, err := client.Get(c, &storepb.GetRequest{Key: req.Key, Namespace: req.Namespace, Cloud: req.Cloud})
	if err != nil {
		return nil, err
	}
	return &invisinetspb.GetValueResponse{Value: response.Value}, nil
}

// Set a value in the KV store
func (s *ControllerServer) SetValue(c context.Context, req *invisinetspb.SetValueRequest) (*invisinetspb.SetValueResponse, error) {
	conn, err := grpc.Dial(s.localKVStoreService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := storepb.NewKVStoreClient(conn)
	_, err = client.Set(c, &storepb.SetRequest{Key: req.Key, Value: req.Value, Namespace: req.Namespace, Cloud: req.Cloud})
	if err != nil {
		return nil, err
	}
	return &invisinetspb.SetValueResponse{}, nil
}

// Delete a value in the KV store
func (s *ControllerServer) DeleteValue(c context.Context, req *invisinetspb.DeleteValueRequest) (*invisinetspb.DeleteValueResponse, error) {
	conn, err := grpc.Dial(s.localKVStoreService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := storepb.NewKVStoreClient(conn)
	_, err = client.Delete(c, &storepb.DeleteRequest{Key: req.Key, Namespace: req.Namespace, Cloud: req.Cloud})
	if err != nil {
		return nil, err
	}
	return &invisinetspb.DeleteValueResponse{}, nil
}

// Setup and run the server
func Setup(configPath string) {
	// Read the config
	f, err := os.Open(configPath)
	if err != nil {
		fmt.Println(err.Error())
	}
	defer f.Close()

	var cfg config.Config
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		fmt.Println(err.Error())
	}

	// Populate server info
	server := ControllerServer{
		pluginAddresses:           make(map[string]string),
		usedBgpPeeringIpAddresses: make(map[string][]string),
		namespace:                 "default",
	}
	server.config = cfg
	server.localTagService = cfg.TagService.Host + ":" + cfg.TagService.Port
	server.localKVStoreService = cfg.KVStore.Host + ":" + cfg.KVStore.Port

	for _, c := range server.config.CloudPlugins {
		server.pluginAddresses[c.Name] = c.Host + ":" + c.Port
	}

	// Setup GRPC server
	lis, err := net.Listen("tcp", cfg.Server.Host+":"+cfg.Server.RpcPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	invisinetspb.RegisterControllerServer(grpcServer, &server)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			fmt.Println(err.Error())
		}
	}()

	// Setup URL router
	router := gin.Default()
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	router.GET(GetPermitListRulesURL, server.permitListGet)
	router.POST(AddPermitListRulesURL, server.permitListRulesBulkAdd)
	router.POST(PermitListRulePOSTURL, server.permitListRuleAdd)
	router.PUT(PermitListRulePUTURL, server.permitListRuleAdd)
	router.POST(DeletePermitListRulesURL, server.permitListRulesDelete)
	router.DELETE(PermitListRulePUTURL, server.permitListRuleDelete)
	router.PUT(CreateResourcePUTURL, server.resourceCreate)
	router.POST(CreateResourcePOSTURL, server.resourceCreate)
	router.GET(GetTagURL, server.getTag)
	router.POST(ResolveTagURL, server.resolveTag)
	router.POST(SetTagURL, server.setTag)
	router.DELETE(DeleteTagURL, server.deleteTag)
	router.DELETE(DeleteTagMemberURL, server.deleteTagMember)
	router.GET(ListNamespacesURL, server.listNamespaces)

	// Run server
	err = router.Run(server.config.Server.Host + ":" + server.config.Server.Port)
	if err != nil {
		fmt.Println(err.Error())
	}
}
