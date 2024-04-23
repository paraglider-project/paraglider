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
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	redis "github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	ibmCommon "github.com/paraglider-project/paraglider/pkg/ibm_plugin"
	sdk "github.com/paraglider-project/paraglider/pkg/ibm_plugin/sdk"
	"github.com/paraglider-project/paraglider/pkg/paragliderpb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

type IBMPluginServer struct {
	paragliderpb.UnimplementedCloudPluginServer
	cloudClient            map[string]*sdk.CloudClient
	orchestratorServerAddr string
}

var defaultRegion = "us-east"

// setupCloudClient fetches the cloud client for a resgroup and region from the map if cached, or creates a new one.
// This function should be the only way the IBM plugin server to get a client
func (s *IBMPluginServer) setupCloudClient(resourceGroupID, region string) (*sdk.CloudClient, error) {
	clientKey := getClientMapKey(resourceGroupID, region)
	if client, ok := s.cloudClient[clientKey]; ok {
		return client, nil
	}
	client, err := sdk.NewIBMCloudClient(resourceGroupID, region)
	if err != nil {
		utils.Log.Println("Failed to set up IBM clients with error:", err)
		return nil, err
	}
	s.cloudClient[clientKey] = client
	return client, nil
}

// getAllClientsForVPCs returns the paraglider VPC IDs and the corresponding clients that are present in all the regions
func (s *IBMPluginServer) getAllClientsForVPCs(cloudClient *sdk.CloudClient, resourceGroupName string, resolveID bool) (map[string]*sdk.CloudClient, error) {
	cloudClients := make(map[string]*sdk.CloudClient)
	vpcsData, err := cloudClient.GetParagliderTaggedResources(sdk.VPC, []string{}, sdk.ResourceQuery{})
	if err != nil {
		return nil, err
	}
	for _, vpcData := range vpcsData {
		if vpcData.Region != cloudClient.Region() {
			cloudClient, err = s.setupCloudClient(resourceGroupName, vpcData.Region)
			if err != nil {
				return nil, err
			}
		}
		cloudClients[vpcData.ID] = cloudClient
	}
	return cloudClients, nil
}

// CreateResource creates the specified resource (instance and cluster).
func (s *IBMPluginServer) CreateResource(c context.Context, resourceDesc *paragliderpb.CreateResourceRequest) (*paragliderpb.CreateResourceResponse, error) {
	var vpcID *string
	var subnetID string
	utils.Log.Printf("Creating resource %s in deployment %s\n", resourceDesc.Name, resourceDesc.Deployment.Id)
	zone, err := getZoneFromDesc(resourceDesc.Description)
	if err != nil {
		return nil, err
	}
	region, err := ibmCommon.ZoneToRegion(zone)
	if err != nil {
		return nil, err
	}

	rInfo, err := getResourceMeta(resourceDesc.Deployment.Id)
	if err != nil {
		return nil, err
	}

	cloudClient, err := s.setupCloudClient(rInfo.ResourceGroup, region)
	if err != nil {
		return nil, err
	}

	res, err := cloudClient.GetResourceHandlerFromDesc(resourceDesc.Description)
	if err != nil {
		return nil, err
	}

	// get VPCs in the request's namespace which can be shared between resources created
	vpcsData, err := cloudClient.GetParagliderTaggedResources(sdk.VPC, []string{resourceDesc.Deployment.Namespace, sdk.SharedVPC},
		sdk.ResourceQuery{Region: region})
	if err != nil {
		return nil, err
	}

	for _, vpcs := range vpcsData {
		if !res.IsExclusiveNetworkNeeded() {
			// Use an existing vpcID which is not an exclusive vpc used by an pre-existing resource
			vpcID = &vpcs.ID
			break
		}
	}

	if vpcID == nil {
		utils.Log.Printf("Creating a VPC (exclusive=%v).\n", res.IsExclusiveNetworkNeeded())
		vpc, err := cloudClient.CreateVPC([]string{resourceDesc.Deployment.Namespace}, res.IsExclusiveNetworkNeeded())
		if err != nil {
			return nil, err
		}
		vpcID = vpc.ID
	}

	// get subnets of VPC
	requiredTags := []string{*vpcID, resourceDesc.Deployment.Namespace}
	subnetsData, err := cloudClient.GetParagliderTaggedResources(sdk.SUBNET, requiredTags,
		sdk.ResourceQuery{Zone: zone})
	if err != nil {
		return nil, err
	}
	if len(subnetsData) == 0 {
		// No existing subnets in the specified VPC
		utils.Log.Printf("Getting address space from orchestrator\n")

		// Find unused address space and create a subnet in it.
		conn, err := grpc.NewClient(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		client := paragliderpb.NewControllerClient(conn)
		resp, err := client.FindUnusedAddressSpaces(context.Background(), &paragliderpb.FindUnusedAddressSpacesRequest{})
		if err != nil {
			return nil, err
		}
		utils.Log.Printf("Using %s address space", resp.AddressSpaces[0])
		subnet, err := cloudClient.CreateSubnet(*vpcID, zone, resp.AddressSpaces[0], requiredTags)
		if err != nil {
			return nil, err
		}
		subnetID = *subnet.ID
	} else {
		// Pick the existent subnet in the zone (given premise: one paraglider subnet per zone and namespace).
		subnetID = subnetsData[0].ID
	}

	// Create the resource in the chosen subnet
	resource, err := res.CreateResource(resourceDesc.Name, *vpcID, subnetID, requiredTags, resourceDesc.Description)
	if err != nil {
		return nil, err
	}

	return &paragliderpb.CreateResourceResponse{Name: resource.Name, Uri: resource.URI, Ip: resource.IP}, nil
}

// GetUsedAddressSpaces returns a list of address spaces used by either user's or paraglider' subnets,
// for each paraglider vpc.
func (s *IBMPluginServer) GetUsedAddressSpaces(ctx context.Context, req *paragliderpb.GetUsedAddressSpacesRequest) (*paragliderpb.GetUsedAddressSpacesResponse, error) {
	resp := &paragliderpb.GetUsedAddressSpacesResponse{}
	resp.AddressSpaceMappings = make([]*paragliderpb.AddressSpaceMapping, len(req.Deployments))
	for i, deployment := range req.Deployments {
		resp.AddressSpaceMappings[i] = &paragliderpb.AddressSpaceMapping{
			Cloud:     utils.IBM,
			Namespace: deployment.Namespace,
		}
		utils.Log.Printf("Getting used address spaces for deployment : %v\n", deployment.Id)
		rInfo, err := getResourceMeta(deployment.Id)
		if err != nil {
			return nil, err
		}
		region, err := ibmCommon.ZoneToRegion(rInfo.Zone)
		if err != nil {
			// No region specified, use default region
			region = defaultRegion
		}

		cloudClient, err := s.setupCloudClient(rInfo.ResourceGroup, region)
		if err != nil {
			return nil, err
		}
		// get all VPCs and corresponding clients to collect all address spaces
		clients, err := s.getAllClientsForVPCs(cloudClient, rInfo.ResourceGroup, true)
		if err != nil {
			utils.Log.Print("Failed to get paraglider tagged VPCs\n")
			return nil, err
		}
		for vpcID, client := range clients {
			subnets, err := client.GetSubnetsInVpcRegionBound(vpcID)
			if err != nil {
				return nil, err
			}
			for _, subnet := range subnets {
				resp.AddressSpaceMappings[i].AddressSpaces = append(resp.AddressSpaceMappings[i].AddressSpaces, *subnet.Ipv4CIDRBlock)
			}
		}
	}

	return resp, nil
}

// GetPermitList returns security rules of security groups associated with the specified resource.
func (s *IBMPluginServer) GetPermitList(ctx context.Context, req *paragliderpb.GetPermitListRequest) (*paragliderpb.GetPermitListResponse, error) {
	rInfo, err := getResourceMeta(req.Resource)
	if err != nil {
		return nil, err
	}
	region, err := ibmCommon.ZoneToRegion(rInfo.Zone)
	if err != nil {
		return nil, err
	}

	cloudClient, err := s.setupCloudClient(rInfo.ResourceGroup, region)
	if err != nil {
		return nil, err
	}

	res, err := cloudClient.GetResourceHandlerFromID(req.Resource)
	if err != nil {
		return nil, err
	}
	// verify specified resource match the specified namespace
	if isInNamespace, err := res.IsInNamespace(req.Namespace, region); !isInNamespace || err != nil {
		return nil, fmt.Errorf("specified resource %v doesn't exist in namespace: %v",
			rInfo.ResourceID, req.Namespace)
	}
	utils.Log.Printf("Getting permit lists for resource: %s\n", rInfo.ResourceID)

	securityGroupID, err := res.GetSecurityGroupID()
	if err != nil {
		return nil, err
	}
	sgRules, err := cloudClient.GetSecurityRulesOfSG(securityGroupID)
	if err != nil {
		return nil, err
	}
	paragliderRules, err := sdk.IBMToParagliderRules(sgRules)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := paragliderpb.NewControllerClient(conn)

	// Get the permitlist names from the rule ID
	for _, rule := range paragliderRules {
		//IBM rule ID is transiently stored in rule name during translation
		ruleName, err := getRuleValFromStore(ctx, client, rule.Name, req.Namespace)
		if err != nil {
			utils.Log.Printf("Failed to get value from KVstore for rule %s: %v.", ruleName, err)
		}
		utils.Log.Printf("Got %s rule name for ID : %s", ruleName, rule.Name)
		rule.Name = ruleName
	}
	return &paragliderpb.GetPermitListResponse{Rules: paragliderRules}, nil
}

// AddPermitListRules attaches security group rules to the specified resource in PermitList.AssociatedResource.
func (s *IBMPluginServer) AddPermitListRules(ctx context.Context, req *paragliderpb.AddPermitListRulesRequest) (*paragliderpb.AddPermitListRulesResponse, error) {

	utils.Log.Printf("Adding PermitListRules %v, %v. namespace :%s \n ", req.Resource, req.Rules, req.Namespace)
	rInfo, err := getResourceMeta(req.Resource)
	if err != nil {
		return nil, err
	}
	region, err := ibmCommon.ZoneToRegion(rInfo.Zone)
	if err != nil {
		utils.Log.Printf("Failed to convert zone to region: %v\n", err)
		return nil, err
	}
	utils.Log.Printf("%s, %s, %s\n", rInfo.ResourceGroup, region, rInfo.ResourceID)
	cloudClient, err := s.setupCloudClient(rInfo.ResourceGroup, region)
	if err != nil {
		utils.Log.Printf("Failed to get cloud client: %v\n", err)
		return nil, err
	}

	res, err := cloudClient.GetResourceHandlerFromID(req.Resource)
	if err != nil {
		return nil, err
	}
	// verify specified resource match the specified namespace
	if isInNamespace, err := res.IsInNamespace(req.Namespace, region); !isInNamespace || err != nil {
		return nil, fmt.Errorf("specified resource %v doesn't exist in namespace: %v",
			rInfo.ResourceID, req.Namespace)
	}

	// get security group of the resource
	paragliderSgsData, err := cloudClient.GetParagliderTaggedResources(sdk.SG, []string{res.GetID()}, sdk.ResourceQuery{Region: region})
	if err != nil {
		utils.Log.Printf("Failed to get paraglider tagged resources %v: %v.\n", res.GetID(), err)
		return nil, err
	}
	if len(paragliderSgsData) == 0 {
		utils.Log.Printf("No security groups were found for resource %v\n", res.GetID())
		return nil, fmt.Errorf("no security groups were found for resource %v", res.GetID())
	}
	// up to a single paraglider security group can exist per resource (queried resource by tag=resourceID)
	requestSGID := paragliderSgsData[0].ID

	// get VPC of the resource specified in the request
	requestVPCData, err := res.GetVPC()
	if err != nil {
		utils.Log.Printf("Failed to get VPC: %v.\n", err)
		return nil, err
	}
	utils.Log.Printf("Adding rule to SG ID : %s\n", requestSGID)
	// translate paraglider rules to IBM rules to compare hash values with current rules.
	ibmRulesToAdd, err := sdk.ParagliderToIBMRules(requestSGID, req.Rules)
	if err != nil {
		utils.Log.Printf("Failed to convert to ibm rules : %v.", err)
		return nil, err
	}
	utils.Log.Printf("Translated permit list to intermediate IBM Rule : %v\n", ibmRulesToAdd)

	// get current rules in SG and record their hash values
	sgRules, err := cloudClient.GetSecurityRulesOfSG(requestSGID)
	if err != nil {
		return nil, err
	}

	// Get used address spaces of all clouds
	controllerConn, err := grpc.NewClient(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("unable to establish connection with orchestrator: %w", err)
	}
	defer controllerConn.Close()
	controllerClient := paragliderpb.NewControllerClient(controllerConn)
	addressSpaceMappings, err := controllerClient.GetUsedAddressSpaces(context.Background(), &paragliderpb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("unable to get used address spaces: %w", err)
	}
	gwID := "" // global transit gateway ID for vpc-peering.
	for _, invisinetsRule := range req.Rules {
		// translate invisinets rule to IBM rules to compare hash values with current rules.
		// multiple ibm rules can be returned due to multiple possible targets
		ibmRules, err := sdk.ParagliderToIBMRule(requestSGID, invisinetsRule)
		if err != nil {
			utils.Log.Printf("Failed to get remote vpc: %v.\n", err)
			return nil, err
		}

		// peeringCloudInfos contains cloud info associated with the specified rule's targets
		peeringCloudInfos, err := utils.GetPermitListRulePeeringCloudInfo(invisinetsRule, addressSpaceMappings.AddressSpaceMappings)
		if err != nil {
			return nil, fmt.Errorf("unable to get peering cloud infos: %w", err)
		}
		// connect clouds if needed
		for i, peeringCloudInfo := range peeringCloudInfos {
			if peeringCloudInfo == nil { // public IP address
				continue
			}
			if peeringCloudInfo.Cloud != utils.IBM {
				// Create VPN connections
				connectCloudsReq := &paragliderpb.ConnectCloudsRequest{
					CloudA:          utils.IBM,
					CloudANamespace: req.Namespace,
					CloudB:          peeringCloudInfo.Cloud,
					CloudBNamespace: peeringCloudInfo.Namespace,
				}
				_, err := controllerClient.ConnectClouds(ctx, connectCloudsReq)
				if err != nil {
					return nil, fmt.Errorf("unable to connect clouds : %w", err)
				}
			} else {
				// if rule targets a VPC on IBM, connect them via a transit gateway
				err = s.connectToTransitGatewayIfNeeded(cloudClient, ibmRules[i], gwID, rInfo.ResourceGroup, *requestVPCData.CRN, region)
				if err != nil {
					return nil, err
				}
			}
		}

		// add rule to security group if aren't duplicates
		for _, ibmRule := range ibmRules {
			rulesHashValues := make(map[uint64]bool)
			_, err = cloudClient.GetUniqueSGRules(sgRules, rulesHashValues)
			if err != nil {
				utils.Log.Printf("Failed to get unique sg rules: %v.\n", err)
				return nil, err
			}
			// compute hash value of rules, disregarding the ID field.
			ruleHashValue, err := ibmCommon.GetStructHash(ibmRule, []string{"ID"})
			if err != nil {
				utils.Log.Printf("Failed to compute hash: %v.\n", err)
				return nil, err
			}
			// avoid adding duplicate rules (when hash values match)
			if rulesHashValues[ruleHashValue] {
				utils.Log.Printf("Rule %+v already exists for security group ID %v.\n", ibmRule, requestSGID)
				return &paragliderpb.AddPermitListRulesResponse{}, nil
			}

			ruleID, err := cloudClient.AddSecurityGroupRule(ibmRule)
			if err != nil {
				utils.Log.Printf("Failed to add security group rule: %v.\n", err)
				return nil, err
			}
			utils.Log.Printf("Attached rule %s(%s), %+v\n", ruleID, ibmRule.ID, ibmRule)

			// Check if there exists a rule with the permitlist name
			oldRuleID, err := getRuleValFromStore(ctx, controllerClient, ibmRule.ID, req.Namespace)
			if err != nil && !strings.Contains(err.Error(), string(redis.Nil)) {
				// In case of failure to get/set KV from store, ensure the existing ruled is deleted
				// to ensure, there are no zombie rules
				utils.Log.Printf("Failed to retrieve from KV store for rule %s: %v.", ibmRule.ID, err)
				err = cloudClient.DeleteSecurityGroupRule(requestSGID, ruleID)
				if err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("failed to get from kv store %v", err)
			}

			if oldRuleID != "" {
				// Existing rule found with the same permitlist name
				err = cloudClient.DeleteSecurityGroupRule(requestSGID, oldRuleID)
				if err != nil {
					return nil, err
				}
				utils.Log.Printf("Cleaning up old rule %s with same permitlist name %s", oldRuleID, ibmRule.ID)
			}
			// The intermediate representation ibmRule.ID stores the permitlist name
			err = setRuleValToStore(ctx, controllerClient, ibmRule.ID, ruleID, req.Namespace)
			if err != nil {
				utils.Log.Printf("Failed to set KV store for rule %s: %v.", ibmRule.ID, err)
				err = cloudClient.DeleteSecurityGroupRule(requestSGID, ruleID)
				if err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("failed to set kv store: %v", err)
			}
			// Store the reverse representation to be used to retrieve permitlist name for getpermitlist requests
			err = setRuleValToStore(ctx, controllerClient, ruleID, ibmRule.ID, req.Namespace)
			if err != nil {
				utils.Log.Printf("Failed to set KV store for rule %s: %v.", ibmRule.ID, err)
				err = cloudClient.DeleteSecurityGroupRule(requestSGID, ruleID)
				if err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("failed to set kv store: %v", err)
			}
		}
	}

	return &paragliderpb.AddPermitListRulesResponse{}, nil
}

// connects the VPC matching the specified vpcCRN, and the remote VPC containing the address space in the specified ibmRule,
// to the global transit gateway, if such a VPC exists
func (s *IBMPluginServer) connectToTransitGatewayIfNeeded(cloudClient *sdk.CloudClient, ibmRule sdk.SecurityGroupRule, gwID, resourceGroupName, vpcCRN, region string) error {

	// get the VPCs and clients to search if the remote IP resides in any of them
	clients, err := s.getAllClientsForVPCs(cloudClient, resourceGroupName, true)
	if err != nil {
		return err
	}
	remoteVPC := ""
	var remoteVPCClient *sdk.CloudClient // client scoped to the region of the remote VPC
	for vpcID, client := range clients {
		if isRemoteInVPC, _ := client.IsRemoteInVPC(vpcID, ibmRule.Remote); isRemoteInVPC {
			remoteVPC = vpcID
			remoteVPCClient = client
			break
		}
	}
	vpcID := sdk.CRN2ID(vpcCRN)
	// if the remote resides inside an invisinets VPC that isn't the request VM's VPC, connect them
	if remoteVPC != "" && remoteVPC != vpcID {
		utils.Log.Printf("The following rule's remote is targeting a different IBM VPC\nRule: %+v\nVPC:%+v", ibmRule, remoteVPC)
		// fetch or create transit gateway
		if len(gwID) == 0 { // lookup optimization, use the already fetched gateway ID if possible
			gwID, err = cloudClient.GetOrCreateTransitGateway(region)
			if err != nil {
				return err
			}
		}
		// connect the VPC of the request's VM to the transit gateway.
		err = cloudClient.ConnectVPC(gwID, vpcCRN)
		if err != nil {
			return err
		}

		remoteVPC, err := remoteVPCClient.GetVPCByID(remoteVPC)
		if err != nil {
			return err
		}

		// connect remote VPC to the transit gateway.
		err = remoteVPCClient.ConnectVPC(gwID, *remoteVPC.CRN)
		if err != nil {
			return err
		}
	}
	return nil
}

// DeletePermitListRules deletes security group rules matching the attributes of the rules contained in the relevant Security group
func (s *IBMPluginServer) DeletePermitListRules(ctx context.Context, req *paragliderpb.DeletePermitListRulesRequest) (*paragliderpb.DeletePermitListRulesResponse, error) {
	rInfo, err := getResourceMeta(req.Resource)
	if err != nil {
		return nil, err
	}
	region, err := ibmCommon.ZoneToRegion(rInfo.Zone)
	if err != nil {
		return nil, err
	}

	cloudClient, err := s.setupCloudClient(rInfo.ResourceGroup, region)
	if err != nil {
		return nil, err
	}

	res, err := cloudClient.GetResourceHandlerFromID(req.Resource)
	if err != nil {
		return nil, err
	}

	// verify specified resource match the specified namespace
	if isInNamespace, err := res.IsInNamespace(req.Namespace, region); !isInNamespace || err != nil {
		return nil, fmt.Errorf("specified resource %v doesn't exist in namespace: %v",
			rInfo.ResourceID, req.Namespace)
	}

	paragliderSgsData, err := cloudClient.GetParagliderTaggedResources(sdk.SG, []string{res.GetID()}, sdk.ResourceQuery{Region: region})
	if err != nil {
		return nil, err
	}
	if len(paragliderSgsData) == 0 {
		return nil, fmt.Errorf("no security groups were found for resource %v", res.GetID())
	}
	// assuming up to a single paraglider subnet can exist per zone
	paragliderSgID := paragliderSgsData[0].ID

	conn, err := grpc.NewClient(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := paragliderpb.NewControllerClient(conn)

	for _, ruleName := range req.RuleNames {
		ruleID, err := getRuleValFromStore(ctx, client, ruleName, req.Namespace)
		if err != nil && !strings.Contains(err.Error(), string(redis.Nil)) {
			return nil, fmt.Errorf("failed to get from kv store %v", err)
		}
		if ruleID == "" {
			utils.Log.Printf("Rule %s not found in KVstore.", ruleName)
			continue
		}
		utils.Log.Printf("Got %s rule ID for name : %s", ruleID, ruleName)

		err = cloudClient.DeleteSecurityGroupRule(paragliderSgID, ruleID)
		if err != nil {
			return nil, err
		}
		utils.Log.Printf("Deleted rule %v", ruleID)

		// delete the references form the kv store
		err = delRuleValFromStore(ctx, client, ruleName, req.Namespace)
		if err != nil {
			utils.Log.Printf("Failed to delete %s from kvstore", ruleName)
		}
		err = delRuleValFromStore(ctx, client, ruleID, req.Namespace)
		if err != nil {
			utils.Log.Printf("Failed to delete %s from kvstore", ruleID)
		}
	}

	return &paragliderpb.DeletePermitListRulesResponse{}, nil
}

func (s *IBMPluginServer) CreateVpnGateway(ctx context.Context, req *paragliderpb.CreateVpnGatewayRequest) (*paragliderpb.CreateVpnGatewayResponse, error) {
	rInfo, err := getResourceMeta(req.Deployment.Id)
	if err != nil {
		return nil, err
	}
	region, err := ibmCommon.ZoneToRegion(rInfo.Zone)
	if err != nil {
		return nil, err
	}
	cloudClient, err := s.setupCloudClient(rInfo.ResourceGroup, region)
	if err != nil {
		return nil, err
	}
	ipAddresses, err := cloudClient.CreateRouteBasedVPN(req.Deployment.Namespace)
	if err != nil {
		return nil, err
	}

	return &paragliderpb.CreateVpnGatewayResponse{GatewayIpAddresses: ipAddresses}, nil
}

// creates VPN connection
func (s *IBMPluginServer) CreateVpnConnections(ctx context.Context, req *paragliderpb.CreateVpnConnectionsRequest) (*paragliderpb.BasicResponse, error) {
	rInfo, err := getResourceMeta(req.Deployment.Id)
	if err != nil {
		return nil, err
	}
	region, err := ibmCommon.ZoneToRegion(rInfo.Zone)
	if err != nil {
		return nil, err
	}
	cloudClient, err := s.setupCloudClient(rInfo.ResourceGroup, region)
	if err != nil {
		return nil, err
	}
	// get VPN in the namespace and region
	vpns, err := cloudClient.GetVPNsInNamespaceRegion(req.Deployment.Namespace, region)
	if err != nil {
		return nil, err
	}

	// if vpn doesn't exist before invoking this method return an error
	// needless to check [vpn instances>1] case, since GetVPNInNamespaceRegion is filtered by region,
	// 		and implementation guarantees one VPN per namespace and region.
	if len(vpns) == 0 {
		return nil, fmt.Errorf("No vpn found in namespace %v and region %v", req.Deployment.Namespace, region)
	}
	vpn := vpns[0]

	for _, peerVPNIPAddress := range req.GatewayIpAddresses {
		err := cloudClient.CreateVPNConnectionRouteBased(vpn.ID, peerVPNIPAddress, req.SharedKey, req.RemoteAddress, req.Cloud)
		if err != nil {
			return nil, err
		}
	}

	return &paragliderpb.BasicResponse{Success: true}, nil
}

// returns IP addresses of VPNs referenced in request
func (s *IBMPluginServer) GetUsedBgpPeeringIpAddresses(ctx context.Context, req *paragliderpb.GetUsedBgpPeeringIpAddressesRequest) (*paragliderpb.GetUsedBgpPeeringIpAddressesResponse, error) {
	resp := &paragliderpb.GetUsedBgpPeeringIpAddressesResponse{}
	// collect public IP addresses from each VPN that is referenced by deployments specified in the request
	for _, deployment := range req.Deployments {
		rInfo, err := getResourceMeta(deployment.Id)
		if err != nil {
			return nil, err
		}
		region, err := ibmCommon.ZoneToRegion(rInfo.Zone)
		if err != nil {
			return nil, err
		}
		cloudClient, err := s.setupCloudClient(rInfo.ResourceGroup, region)
		if err != nil {
			return nil, err
		}

		// gets all VPNs associated with specified namespace
		vpns, err := cloudClient.GetVPNsInNamespaceRegion(deployment.Namespace, "")
		if err != nil {
			return nil, err
		}
		// collects public IPs of each VPN
		for _, vpn := range vpns {
			vpnRegion := vpn.Region
			cloudClient, err := s.setupCloudClient(rInfo.ResourceGroup, vpnRegion)
			if err != nil {
				return nil, err
			}
			ips, err := cloudClient.GetVPNIPs(vpn.ID)
			if err != nil {
				return nil, err
			}
			resp.IpAddresses = append(resp.IpAddresses, ips...)
		}
	}
	return resp, nil
}

// Setup starts up the plugin server and stores the orchestrator server address.
func Setup(port int, orchestratorServerAddr string) *IBMPluginServer {
	pluginServerAddress := "localhost"
	lis, err := net.Listen("tcp", fmt.Sprintf("%v:%d", pluginServerAddress, port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	ibmServer := &IBMPluginServer{
		cloudClient:            make(map[string]*sdk.CloudClient),
		orchestratorServerAddr: orchestratorServerAddr,
	}
	paragliderpb.RegisterCloudPluginServer(grpcServer, ibmServer)
	utils.Log.Printf("\nStarting IBM plugin server on: %v:%v\n", pluginServerAddress, port)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			fmt.Println(err.Error())
		}
	}()
	return ibmServer
}
