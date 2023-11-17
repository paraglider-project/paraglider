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

	cfg "github.com/NetSys/invisinets/pkg/frontend/config"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	tagservicepb "github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
	utils "github.com/NetSys/invisinets/pkg/utils"
)

const (
	GetPermitListRulesURL    string = "/namespaces/:namespace/clouds/:cloud/resources/:resourceName/rules"
	AddPermitListRulesURL    string = "/namespaces/:namespace/clouds/:cloud/resources/:resourceName/rules"
	DeletePermitListRulesURL string = "/namespaces/:namespace/clouds/:cloud/resources/:resourceName/rules"
	CreateResourceURL        string = "/namespaces/:namespace/clouds/:cloud/resources/:resourceName/create"
	GetTagURL                string = "/tags/:tag"
	ResolveTagURL            string = "/tags/:tag/resolve"
	SetTagURL                string = "/tags/:tag"
	DeleteTagURL             string = "/tags/:tag"
	DeleteTagMemberURL       string = "/tags/:tag/members/:member"
	ListNamespacesURL        string = "/namespaces"
)

type Warning struct {
	Message string
}

type ControllerServer struct {
	invisinetspb.UnimplementedControllerServer
	pluginAddresses   map[string]string
	usedAddressSpaces map[string]map[string][]string
	localTagService   string
	config            cfg.Config
}

type resourceInfo struct {
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

// TODO NOW: Document and add tests
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

// TODO NOW: Document and add tests
func (s *ControllerServer) getAndValidateResourceParams(c *gin.Context, resolveTag bool) (*resourceInfo, string, error) {
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

		return &resourceInfo{name: tag, uri: uri, namespace: namespace, cloud: cloud}, cloudClient, nil
	} else {
		return &resourceInfo{name: tag, namespace: namespace, cloud: cloud}, cloudClient, nil
	}
}

// Takes a set of permit list rules and returns the same list with all tags referenced in the original rules resolved to IPs
func (s *ControllerServer) resolvePermitListRules(list *invisinetspb.PermitList, subscribe bool, cloud string) (*invisinetspb.PermitList, error) {
	for _, rule := range list.Rules {
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
							Subscriber: createSubscriberName(list.Namespace, cloud, list.AssociatedResource)})
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
	return list, nil
}

// Get permit list with ID from plugin
func (s *ControllerServer) _permitListGet(namespace string, pluginAddress string, id string) (*invisinetspb.PermitList, error) {
	// Connect to the cloud plugin
	conn, err := grpc.Dial(pluginAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send the GetPermitList RPC
	client := invisinetspb.NewCloudPluginClient(conn)
	emptyresourceId := invisinetspb.ResourceID{Id: id, Namespace: namespace}

	response, err := client.GetPermitList(context.Background(), &emptyresourceId)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Get specified PermitList from given cloud
func (s *ControllerServer) permitListGet(c *gin.Context) {
	resourceInfo, cloudClient, err := s.getAndValidateResourceParams(c, true)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	response, err := s._permitListGet(resourceInfo.namespace, cloudClient, resourceInfo.uri)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, response.Rules)
}

// Add rules to a resource specified in the permit list in the given cloud
func (s *ControllerServer) _permitListRulesAdd(pluginAddress string, permitList *invisinetspb.PermitList, cloud string) (*invisinetspb.BasicResponse, error) {
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
		return nil, err
	}

	return response, nil
}

// Add permit list rules to specified resource
func (s *ControllerServer) permitListRulesAdd(c *gin.Context) {
	resourceInfo, cloudClient, err := s.getAndValidateResourceParams(c, true)
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
	permitList := &invisinetspb.PermitList{Rules: rules, Namespace: resourceInfo.namespace, AssociatedResource: resourceInfo.uri}

	response, err := s._permitListRulesAdd(cloudClient, permitList, resourceInfo.cloud)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"response": response.Message,
	})
}

// Find the tags dereferenced between two versions of a permit list
func diffTagReferences(beforeList *invisinetspb.PermitList, afterList *invisinetspb.PermitList) []string {
	beforeListSet := make(map[string]bool)
	afterListSet := make(map[string]bool)
	tagsDereferenced := []string{}

	for _, rule := range beforeList.Rules {
		for _, tag := range rule.Tags {
			if !isIpAddrOrCidr(tag) {
				beforeListSet[tag] = true
			}
		}
	}

	for _, rule := range afterList.Rules {
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
func (s *ControllerServer) checkAndUnsubscribe(resource *resourceInfo, beforeList *invisinetspb.PermitList, afterList *invisinetspb.PermitList) error {
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
	resourceInfo, cloudClient, err := s.getAndValidateResourceParams(c, true)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Parse rules to delete
	var rules []*invisinetspb.PermitListRule
	if err := c.BindJSON(&rules); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	permitList := &invisinetspb.PermitList{Rules: rules, Namespace: resourceInfo.namespace, AssociatedResource: resourceInfo.uri}

	// Create connection to cloud plugin
	conn, err := grpc.Dial(cloudClient, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}
	defer conn.Close()
	client := invisinetspb.NewCloudPluginClient(conn)

	// First, get the original list
	permitListBefore, err := client.GetPermitList(context.Background(), &invisinetspb.ResourceID{Id: resourceInfo.uri})
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Resolve tags (for correct lookup in cloud plugin) and unsubscribe
	permitList, err = s.resolvePermitListRules(permitList, false, resourceInfo.cloud)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Send RPC to delete the rules
	response, err := client.DeletePermitListRules(context.Background(), permitList)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Then get the final list to tell which tags should be unsubscribed
	permitListAfter, err := client.GetPermitList(context.Background(), &invisinetspb.ResourceID{Id: resourceInfo.uri})
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	// Determine which tags have been dereferenced from the permit list and unsubscribe
	// TODO @smcclure20: Have to do a permit list diff since there is no reverse lookup to see which tags a URI is subscribed to.
	// 					 Supporting this will probably require a database migration (non-KV store)
	if err := s.checkAndUnsubscribe(resourceInfo, permitListBefore, permitListAfter); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"response": response.Message,
	})
}

// Get used address spaces from a specified cloud
func (s *ControllerServer) getAddressSpaces(cloud string, deploymentId string, namespace string) (*invisinetspb.AddressSpaceList, error) {
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
	deployment := invisinetspb.InvisinetsDeployment{Id: deploymentId, Namespace: namespace}
	addressSpaces, err := client.GetUsedAddressSpaces(context.Background(), &deployment)

	return addressSpaces, err
}

// Update local address space map by getting used address spaces from each cloud plugin
func (s *ControllerServer) updateUsedAddressSpacesMap(namespace string) error {
	// Call each cloud to get address spaces used
	for _, cloud := range s.config.Namespaces[namespace].CloudDeployments {
		addressList, err := s.getAddressSpaces(cloud.Name, cloud.Deployment, namespace)
		if err != nil {
			return fmt.Errorf("could not retrieve address spaces for cloud %s (error: %s)", cloud, err.Error())
		}

		if _, ok := s.usedAddressSpaces[namespace]; !ok {
			s.usedAddressSpaces[namespace] = make(map[string][]string)
		}
		s.usedAddressSpaces[namespace][cloud.Name] = addressList.AddressSpaces
	}
	return nil
}

// Get a new address block for a new virtual network
// TODO @smcclure20: Later, this should allocate more efficiently and with different size address blocks (eg, GCP needs larger than Azure since a VPC will span all regions)
func (s *ControllerServer) FindUnusedAddressSpace(c context.Context, ns *invisinetspb.Namespace) (*invisinetspb.AddressSpace, error) {
	err := s.updateUsedAddressSpacesMap(ns.Namespace)
	if err != nil {
		return nil, err
	}
	highestBlockUsed := -1
	for _, addressList := range s.usedAddressSpaces[ns.Namespace] {
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
		return nil, errors.New("all address blocks used")
	}

	newAddressSpace := &invisinetspb.AddressSpace{Address: fmt.Sprintf("10.%d.0.0/16", highestBlockUsed+1)}
	return newAddressSpace, nil
}

// Gets unused address spaces across all clouds
func (s *ControllerServer) GetUsedAddressSpaces(c context.Context, ns *invisinetspb.Namespace) (*invisinetspb.AddressSpaceMappingList, error) {
	err := s.updateUsedAddressSpacesMap(ns.Namespace)
	if err != nil {
		return nil, err
	}

	usedAddressSpaceMappings := &invisinetspb.AddressSpaceMappingList{}
	usedAddressSpaceMappings.AddressSpaceMappings = make([]*invisinetspb.AddressSpaceMapping, len(s.usedAddressSpaces[ns.Namespace]))
	i := 0
	for cloud, addressSpaces := range s.usedAddressSpaces[ns.Namespace] {
		usedAddressSpaceMappings.AddressSpaceMappings[i] = &invisinetspb.AddressSpaceMapping{
			AddressSpaces: addressSpaces,
			Cloud:         cloud,
			Namespace:     ns.Namespace,
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
func (s *ControllerServer) getCloudDeployment(namespace string, cloudName string) string {
	for _, cloud := range s.config.Namespaces[namespace].CloudDeployments {
		if cloud.Name == cloudName {
			return cloud.Deployment
		}
	}
	return ""
}

// Connects two clouds with VPN gateways
func (s *ControllerServer) ConnectClouds(ctx context.Context, req *invisinetspb.ConnectCloudsRequest) (*invisinetspb.BasicResponse, error) {
	if req.CloudA == req.CloudB {
		return nil, fmt.Errorf("must specify different clouds to connect")
	}
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
			return nil, fmt.Errorf("unable to connect to cloud plugin: %w", err)
		}
		defer cloudAConn.Close()
		cloudBClient := invisinetspb.NewCloudPluginClient(cloudBconn)

		ctx := context.Background()

		cloudAInvisinetsDeployment := &invisinetspb.InvisinetsDeployment{Id: s.getCloudDeployment(req.CloudANamespace, req.CloudA), Namespace: req.CloudANamespace}
		cloudACreateVpnGatewayResp, err := cloudAClient.CreateVpnGateway(ctx, cloudAInvisinetsDeployment)
		if err != nil {
			return nil, fmt.Errorf("unable to create vpn gateway in cloud %s: %w", req.CloudA, err)
		}
		cloudBInvisinetsDeployment := &invisinetspb.InvisinetsDeployment{Id: s.getCloudDeployment(req.CloudBNamespace, req.CloudB), Namespace: req.CloudBNamespace}
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
	resourceInfo, cloudClient, err := s.getAndValidateResourceParams(c, false)
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

	c.JSON(http.StatusOK, resourceResp) // TODO @smcclure20: What should the behavior be if the name in the description and URL do not match? Maybe in redoing the rpc interfaces we should have the name come with the request so the plugin can check
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
func clearRuleTargets(rules *invisinetspb.PermitList) *invisinetspb.PermitList {
	for _, rule := range rules.Rules {
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

		permitList, err := s._permitListGet(namespace, cloudClient, uri)
		if err != nil {
			return err
		}

		permitList = clearRuleTargets(permitList)

		_, err = s._permitListRulesAdd(cloudClient, permitList, cloud)
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

// Setup and run the server
func Setup(configPath string) {
	// Read the config
	f, err := os.Open(configPath)
	if err != nil {
		fmt.Println(err.Error())
	}
	defer f.Close()

	var config cfg.Config
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&config)
	if err != nil {
		fmt.Println(err.Error())
	}

	// Populate server info
	server := ControllerServer{pluginAddresses: make(map[string]string), usedAddressSpaces: make(map[string]map[string][]string)}
	server.config = config
	server.localTagService = config.TagService.Host + ":" + config.TagService.Port

	for _, c := range server.config.CloudPlugins {
		server.pluginAddresses[c.Name] = c.Host + ":" + c.Port
	}

	// Setup GRPC server
	lis, err := net.Listen("tcp", config.Server.Host+":"+config.Server.RpcPort)
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
	router.GET(string(GetPermitListRulesURL), server.permitListGet)
	router.POST(string(AddPermitListRulesURL), server.permitListRulesAdd)
	router.DELETE(string(DeletePermitListRulesURL), server.permitListRulesDelete)
	router.POST(string(CreateResourceURL), server.resourceCreate)
	router.GET(string(GetTagURL), server.getTag)
	router.GET(string(ResolveTagURL), server.resolveTag)
	router.POST(string(SetTagURL), server.setTag)
	router.DELETE(string(DeleteTagURL), server.deleteTag)
	router.DELETE(string(DeleteTagMemberURL), server.deleteTagMember)
	router.GET(string(ListNamespacesURL), server.listNamespaces)

	// Run server
	err = router.Run(server.config.Server.Host + ":" + server.config.Server.Port)
	if err != nil {
		fmt.Println(err.Error())
	}
}
