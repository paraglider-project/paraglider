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
	"encoding/json"
	"fmt"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	"github.com/IBM/vpc-go-sdk/vpcv1"
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

// CreateResource creates the specified resource.
// Currently only supports instance creation.
func (s *IBMPluginServer) CreateResource(c context.Context, resourceDesc *paragliderpb.ResourceDescription) (*paragliderpb.CreateResourceResponse, error) {
	var vpcID string
	var subnetID string
	resFields := vpcv1.CreateInstanceOptions{}
	utils.Log.Printf("Creating resource %s in deployment %s\n", resourceDesc.Name, resourceDesc.Deployment.Id)
	// TODO : Support unmarshalling to other struct types of InstancePrototype interface
	resFields.InstancePrototype = &vpcv1.InstancePrototypeInstanceByImage{
		Image:         &vpcv1.ImageIdentityByID{},
		Zone:          &vpcv1.ZoneIdentityByName{},
		Profile:       &vpcv1.InstanceProfileIdentityByName{},
		ResourceGroup: &vpcv1.ResourceGroupIdentityByID{},
	}

	err := json.Unmarshal(resourceDesc.Description, &resFields)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal resource description:%+v", err)
	}
	if resFields.InstancePrototype.(*vpcv1.InstancePrototypeInstanceByImage).Zone.(*vpcv1.ZoneIdentityByName).Name == nil {
		return nil, fmt.Errorf("unspecified zone definition in resource description")
	}
	zone := *resFields.InstancePrototype.(*vpcv1.InstancePrototypeInstanceByImage).Zone.(*vpcv1.ZoneIdentityByName).Name
	region, err := ibmCommon.ZoneToRegion(zone)
	if err != nil {
		return nil, err
	}

	rInfo, err := getResourceIDInfo(resourceDesc.Deployment.Id)
	if err != nil {
		return nil, err
	}

	resFields.InstancePrototype.(*vpcv1.InstancePrototypeInstanceByImage).Name = proto.String(resourceDesc.Name)
	resFields.InstancePrototype.(*vpcv1.InstancePrototypeInstanceByImage).ResourceGroup.(*vpcv1.ResourceGroupIdentityByID).ID = &rInfo.ResourceGroup

	cloudClient, err := s.setupCloudClient(rInfo.ResourceGroup, region)
	if err != nil {
		return nil, err
	}

	// get VPCs in the request's namespace
	vpcsData, err := cloudClient.GetParagliderTaggedResources(sdk.VPC, []string{resourceDesc.Deployment.Namespace},
		sdk.ResourceQuery{Region: region})
	if err != nil {
		return nil, err
	}
	if len(vpcsData) == 0 {
		// No VPC found in the requested namespace and region. Create one.
		utils.Log.Printf("No VPCs found in the region, will be creating.")
		vpc, err := cloudClient.CreateVPC([]string{resourceDesc.Deployment.Namespace})
		if err != nil {
			return nil, err
		}
		vpcID = *vpc.ID
	} else {
		// Assuming a single VPC per region and namespace
		vpcID = vpcsData[0].ID
		utils.Log.Printf("Using existing VPC ID : %s\n", vpcID)
	}

	// get subnets of VPC
	requiredTags := []string{vpcID, resourceDesc.Deployment.Namespace}
	subnetsData, err := cloudClient.GetParagliderTaggedResources(sdk.SUBNET, requiredTags,
		sdk.ResourceQuery{Zone: zone})
	if err != nil {
		return nil, err
	}
	if len(subnetsData) == 0 {
		// No subnets in the specified VPC.
		utils.Log.Printf("No Subnets found in the zone, getting address space from orchestrator\n")

		// Find unused address space and create a subnet in it.
		conn, err := grpc.Dial(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
		subnet, err := cloudClient.CreateSubnet(vpcID, zone, resp.AddressSpaces[0], requiredTags)
		if err != nil {
			return nil, err
		}
		subnetID = *subnet.ID
	} else {
		// Pick the existent subnet in the zone (given premise: one paraglider subnet per zone and namespace).
		subnetID = subnetsData[0].ID
	}

	// Launch an instance in the chosen subnet
	vm, err := cloudClient.CreateInstance(vpcID, subnetID, &resFields, requiredTags)
	if err != nil {
		return nil, err
	}
	// get private IP of newly launched instance
	reservedIP, err := cloudClient.GetInstanceReservedIP(*vm.ID)
	if err != nil {
		return nil, err
	}

	return &paragliderpb.CreateResourceResponse{Name: *vm.Name, Uri: createInstanceID(rInfo.ResourceGroup, zone, *vm.ID), Ip: reservedIP}, nil
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
		rInfo, err := getResourceIDInfo(deployment.Id)
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

// GetPermitList returns security rules of security groups associated with the specified instance.
func (s *IBMPluginServer) GetPermitList(ctx context.Context, req *paragliderpb.GetPermitListRequest) (*paragliderpb.GetPermitListResponse, error) {
	rInfo, err := getResourceIDInfo(req.Resource)
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

	// verify specified instance match the specified namespace
	if isInNamespace, err := cloudClient.IsInstanceInNamespace(
		rInfo.ResourceID, req.Namespace, region); !isInNamespace || err != nil {
		return nil, fmt.Errorf("specified instance: %v doesn't exist in namespace: %v",
			rInfo.ResourceID, req.Namespace)
	}
	utils.Log.Printf("Getting permit lists for instance: %s\n", rInfo.ResourceID)
	securityGroupID, err := cloudClient.GetInstanceSecurityGroupID(rInfo.ResourceID)
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

	return &paragliderpb.GetPermitListResponse{Rules: paragliderRules}, nil
}

// AddPermitListRules attaches security group rules to the specified instance in PermitList.AssociatedResource.
func (s *IBMPluginServer) AddPermitListRules(ctx context.Context, req *paragliderpb.AddPermitListRulesRequest) (*paragliderpb.AddPermitListRulesResponse, error) {

	utils.Log.Printf("Adding PermitListRules %v, %v. namespace :%s \n ", req.Resource, req.Rules, req.Namespace)
	rInfo, err := getResourceIDInfo(req.Resource)
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

	// verify specified instance match the specified namespace
	if isInNamespace, err := cloudClient.IsInstanceInNamespace(
		rInfo.ResourceID, req.Namespace, region); !isInNamespace || err != nil {
		utils.Log.Printf("Not in namespace %v\n", err)
		return nil, fmt.Errorf("specified instance: %v doesn't exist in namespace: %v",
			rInfo.ResourceID, req.Namespace)
	}

	vmID := rInfo.ResourceID

	// get security group of VM
	paragliderSgsData, err := cloudClient.GetParagliderTaggedResources(sdk.SG, []string{vmID}, sdk.ResourceQuery{Region: region})
	if err != nil {
		utils.Log.Printf("Failed to get paraglider tagged resources %v: %v.\n", vmID, err)
		return nil, err
	}
	if len(paragliderSgsData) == 0 {
		utils.Log.Printf("No security groups were found for VM %v\n", vmID)
		return nil, fmt.Errorf("no security groups were found for VM %v", vmID)
	}
	// up to a single paraglider security group can exist per VM (queried resource by tag=vmID)
	requestSGID := paragliderSgsData[0].ID

	// get VPC of the VM specified in the request
	requestVPCData, err := cloudClient.VMToVPCObject(vmID)
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

	gwID := "" // global transit gateway ID for vpc-peering.
	for _, ibmRule := range ibmRulesToAdd {

		// TODO @cohen-j-omer Connect clouds if needed:
		// 1. use the orchestratorClient's GetUsedAddressSpaces to get used addresses.
		// 2. if the rule's remote address resides in one of the clouds create a vpn gateway.

		// get the VPCs and clients to search if the remote IP resides in any of them
		clients, err := s.getAllClientsForVPCs(cloudClient, rInfo.ResourceGroup, false)
		if err != nil {
			utils.Log.Printf("Failed to get remote vpc: %v.\n", err)
			return nil, err
		}
		remoteVPC := ""
		for vpcID, client := range clients {
			if isRemoteInVPC, _ := client.IsRemoteInVPC(vpcID, ibmRule.Remote); isRemoteInVPC {
				remoteVPC = vpcID
				break
			}
		}
		// if the remote resides inside an paraglider VPC that isn't the request VM's VPC, connect them
		if remoteVPC != "" && remoteVPC != *requestVPCData.ID {
			utils.Log.Printf("The following rule's remote is targeting a different IBM VPC\nRule: %+v\nVPC:%+v", ibmRule, remoteVPC)
			// fetch or create transit gateway
			if len(gwID) == 0 { // lookup optimization, use the already fetched gateway ID if possible
				gwID, err = cloudClient.GetOrCreateTransitGateway(region)
				if err != nil {
					return nil, err
				}
			}
			// connect the VPC of the request's VM to the transit gateway.
			// the `remoteVPC` should be connected by a separate symmetric request (e.g. to allow inbound traffic to remote).
			err = cloudClient.ConnectVPC(gwID, *requestVPCData.CRN)
			if err != nil {
				return nil, err
			}
		}
		rulesHashValues := make(map[uint64]bool)
		// get current rules in SG and record their hash values
		sgRules, err := cloudClient.GetSecurityRulesOfSG(requestSGID)
		if err != nil {
			utils.Log.Printf("Failed to get sg rules: %v.\n", err)
			return nil, err
		}
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
		if !rulesHashValues[ruleHashValue] {
			err := cloudClient.AddSecurityGroupRule(ibmRule)
			if err != nil {
				utils.Log.Printf("Failed to add security group rule: %v.\n", err)
				return nil, err
			}
			utils.Log.Printf("Attached rule %+v\n", ibmRule)
		} else {
			utils.Log.Printf("Rule %+v already exists for security group ID %v.\n", ibmRule, requestSGID)
		}
	}

	return &paragliderpb.AddPermitListRulesResponse{}, nil
}

// DeletePermitListRules deletes security group rules matching the attributes of the rules contained in the relevant Security group
func (s *IBMPluginServer) DeletePermitListRules(ctx context.Context, req *paragliderpb.DeletePermitListRulesRequest) (*paragliderpb.DeletePermitListRulesResponse, error) {
	rInfo, err := getResourceIDInfo(req.Resource)
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

	// verify specified instance match the specified namespace
	if isInNamespace, err := cloudClient.IsInstanceInNamespace(
		rInfo.ResourceID, req.Namespace, region); !isInNamespace || err != nil {
		return nil, fmt.Errorf("specified instance: %v doesn't exist in namespace: %v",
			rInfo.ResourceID, req.Namespace)
	}

	vmID := rInfo.ResourceID

	paragliderSgsData, err := cloudClient.GetParagliderTaggedResources(sdk.SG, []string{vmID}, sdk.ResourceQuery{Region: region})
	if err != nil {
		return nil, err
	}
	if len(paragliderSgsData) == 0 {
		return nil, fmt.Errorf("no security groups were found for VM %v", rInfo.ResourceID)
	}
	// assuming up to a single paraglider subnet can exist per zone
	vmParagliderSgID := paragliderSgsData[0].ID

	// TODO @praveingk Deduct rule IDs from the rule names using orchestrator's KV-store
	for _, ruleID := range req.RuleNames {
		err = cloudClient.DeleteSecurityGroupRule(vmParagliderSgID, ruleID)
		if err != nil {
			return nil, err
		}
		utils.Log.Printf("Deleted rule %v", ruleID)
	}

	return &paragliderpb.DeletePermitListRulesResponse{}, nil
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
