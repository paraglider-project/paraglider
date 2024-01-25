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

package ibm

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/IBM/vpc-go-sdk/vpcv1"
	ibmCommon "github.com/NetSys/invisinets/pkg/ibm_plugin"
	sdk "github.com/NetSys/invisinets/pkg/ibm_plugin/sdk"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
	utils "github.com/NetSys/invisinets/pkg/utils"
)

// FrontendServerAddr is exported temporarily until a common way is defined
var FrontendServerAddr string

type ibmPluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
	cloudClient        map[string]*sdk.CloudClient
	frontendServerAddr string
}

func (s *ibmPluginServer) setupCloudClient(resourceGroupName, region string) (*sdk.CloudClient, error) {
	clientKey := getClientMapKey(resourceGroupName, region)
	if client, ok := s.cloudClient[clientKey]; ok {
		return client, nil
	}
	client, err := sdk.NewIBMCloudClient(resourceGroupName, region)
	if err != nil {
		utils.Log.Println("Failed to set up IBM clients with error:", err)
		return nil, err
	}
	s.cloudClient[clientKey] = client
	return client, nil
}

// CreateResource creates the specified resource.
// Currently only supports instance creation.
func (s *ibmPluginServer) CreateResource(c context.Context, resourceDesc *invisinetspb.ResourceDescription) (*invisinetspb.CreateResourceResponse, error) {
	var vpcID string
	var subnetID string
	resFields := vpcv1.CreateInstanceOptions{}

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

	rInfo, err := getResourceIDInfo(resourceDesc.Id)
	if err != nil {
		return nil, err
	}
	region, err := ibmCommon.ZoneToRegion(rInfo.Zone)
	if err != nil {
		return nil, err
	}

	cloudClient, err := s.setupCloudClient(rInfo.ResourceGroupName, region)
	if err != nil {
		return nil, err
	}

	// get VPCs in the request's namespace
	vpcsData, err := cloudClient.GetInvisinetsTaggedResources(sdk.VPC, []string{resourceDesc.Namespace},
		sdk.ResourceQuery{Region: region})
	if err != nil {
		return nil, err
	}
	if len(vpcsData) == 0 {
		// No VPC found in the requested namespace and region. Create one.
		utils.Log.Printf("No VPCs found in the region, will be creating.")
		vpc, err := cloudClient.CreateVPC([]string{resourceDesc.Namespace})
		if err != nil {
			return nil, err
		}
		vpcID = *vpc.ID
	} else {
		// Assuming a single VPC per region and namespace
		vpcID = vpcsData[0].ID
		utils.Log.Printf("Using existing VPC ID : %s", vpcID)
	}

	// get subnets of VPC
	requiredTags := []string{vpcID, resourceDesc.Namespace}
	subnetsData, err := cloudClient.GetInvisinetsTaggedResources(sdk.SUBNET, requiredTags,
		sdk.ResourceQuery{Zone: rInfo.Zone})
	if err != nil {
		return nil, err
	}
	if len(subnetsData) == 0 {
		// No subnets in the specified VPC.
		utils.Log.Printf("No Subnets found in the zone, getting address space from frontend")

		// Find unused address space and create a subnet in it.
		conn, err := grpc.Dial(s.frontendServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		client := invisinetspb.NewControllerClient(conn)
		resp, err := client.FindUnusedAddressSpace(context.Background(), &invisinetspb.Namespace{Namespace: resourceDesc.Namespace})
		if err != nil {
			return nil, err
		}
		utils.Log.Printf("Using %s address space", resp.Address)

		// create subnet
		subnet, err := cloudClient.CreateSubnet(vpcID, rInfo.Zone, resp.Address, requiredTags)
		if err != nil {
			return nil, err
		}
		subnetID = *subnet.ID
	} else {
		// Pick the existent subnet in the zone (given premise: one invisinets subnet per zone and namespace).
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

	return &invisinetspb.CreateResourceResponse{Name: *vm.Name, Uri: *vm.ID, Ip: reservedIP}, nil
}

// GetUsedAddressSpaces returns a list of address spaces used by either user's or invisinets' sunbets,
// for each invisinets vpc.
func (s *ibmPluginServer) GetUsedAddressSpaces(ctx context.Context, deployment *invisinetspb.InvisinetsDeployment) (*invisinetspb.AddressSpaceList, error) {
	var invisinetsAddressSpaces []string
	rInfo, err := getResourceIDInfo(deployment.Id)
	if err != nil {
		return nil, err
	}
	region, err := ibmCommon.ZoneToRegion(rInfo.Zone)
	if err != nil {
		return nil, err
	}

	// using a tmp client to avoid altering the cloud client's region.
	tmpClient, err:=sdk.NewIBMCloudClient(rInfo.ResourceGroupName, region) 
	if err != nil {
		return nil, err
	}

	// get all VPCs (across all namespaces).
	deploymentVpcsData, err := tmpClient.GetInvisinetsTaggedResources(sdk.VPC, []string{}, sdk.ResourceQuery{})
	if err != nil {
		utils.Log.Print("Failed to get invisinets tagged VPCs")
		return nil, err
	}
	utils.Log.Printf("GetUsedAddressSpaces found the following VPCs: %+v", deploymentVpcsData)
	// for each vpc, collect the address space of all subnets, including users'.
	for _, vpcData := range deploymentVpcsData {
		// Set the client on the region of the current VPC, otherwise resources will be out of scope for the client.
		err := tmpClient.UpdateRegion(vpcData.Region)
		if err != nil {
			return nil, err
		}
		subnets, err := tmpClient.GetSubnetsInVpcRegionBound(vpcData.ID)
		if err != nil {
			return nil, err
		}
		for _, subnet := range subnets {
			invisinetsAddressSpaces = append(invisinetsAddressSpaces, *subnet.Ipv4CIDRBlock)
		}
	}

	utils.Log.Printf("Used Address Spaces : %+v", invisinetsAddressSpaces)
	return &invisinetspb.AddressSpaceList{AddressSpaces: invisinetsAddressSpaces}, nil
}

// GetPermitList returns security rules of security groups associated with the specified instance.
func (s *ibmPluginServer) GetPermitList(ctx context.Context, req *invisinetspb.GetPermitListRequest) (*invisinetspb.GetPermitListResponse, error) {
	rInfo, err := getResourceIDInfo(req.Resource)
	if err != nil {
		return nil, err
	}
	region, err := ibmCommon.ZoneToRegion(rInfo.Zone)
	if err != nil {
		return nil, err
	}

	cloudClient, err := s.setupCloudClient(rInfo.ResourceGroupName, region)
	if err != nil {
		return nil, err
	}

	// verify specified instance match the specified namespace
	if isInNamespace, err := cloudClient.IsInstanceInNamespace(
		rInfo.ResourceID, req.Namespace, region); !isInNamespace || err != nil {
		return nil, fmt.Errorf("Specified instance: %v doesn't exist in namespace: %v.",
			rInfo.ResourceID, req.Namespace)
	}

	securityGroupID, err := cloudClient.GetInstanceSecurityGroupID(rInfo.ResourceID)
	if err != nil {
		return nil, err
	}
	sgRules, err := cloudClient.GetSecurityRulesOfSG(securityGroupID)
	if err != nil {
		return nil, err
	}
	invisinetsRules, err := sdk.IBMToInvisinetsRules(sgRules)
	if err != nil {
		return nil, err
	}

	return &invisinetspb.GetPermitListResponse{Rules: invisinetsRules}, nil
}

// AddPermitListRules attaches security group rules to the specified instance in PermitList.AssociatedResource.
func (s *ibmPluginServer) AddPermitListRules(ctx context.Context, req *invisinetspb.AddPermitListRulesRequest) (*invisinetspb.AddPermitListRulesResponse, error) {
	rInfo, err := getResourceIDInfo(req.Resource)
	if err != nil {
		return nil, err
	}
	region, err := ibmCommon.ZoneToRegion(rInfo.Zone)
	if err != nil {
		return nil, err
	}

	cloudClient, err := s.setupCloudClient(rInfo.ResourceGroupName, region)
	if err != nil {
		return nil, err
	}

	// verify specified instance match the specified namespace
	if isInNamespace, err := cloudClient.IsInstanceInNamespace(
		rInfo.ResourceID, req.Namespace, region); !isInNamespace || err != nil {
		return nil, fmt.Errorf("Specified instance: %v doesn't exist in namespace: %v.",
			rInfo.ResourceID, req.Namespace)
	}

	// Get the VM ID from the resource ID (typically refers to VM Name)
	vmData, err := cloudClient.GetInstanceData(rInfo.ResourceID)
	if err != nil {
		return nil, err
	}
	vmID := *vmData.ID
	// get security group of VM
	invisinetsSgsData, err := cloudClient.GetInvisinetsTaggedResources(sdk.SG, []string{vmID}, sdk.ResourceQuery{Region: region})
	if err != nil {
		return nil, err
	}
	if len(invisinetsSgsData) == 0 {
		return nil, fmt.Errorf("no security groups were found for VM %v", vmID)
	}
	// up to a single invisinets security group can exist per VM (queried resource by tag=vmID)
	requestSGID := invisinetsSgsData[0].ID

	// get VPC of the VM specified in the request
	requestVPCData, err := cloudClient.VMToVPCObject(vmID)
	if err != nil {
		return nil, err
	}

	// translate invisinets rules to IBM rules to compare hash values with current rules.
	ibmRulesToAdd, err := sdk.InvisinetsToIBMRules(requestSGID, req.Rules)
	if err != nil {
		return nil, err
	}

	gwID := "" // global transit gateway ID for vpc-peering.
	for _, ibmRule := range ibmRulesToAdd {

		// TODO @cohen-j-omer Connect clouds if needed:
		// 1. use the controllerClient's GetUsedAddressSpaces to get used addresses.
		// 2. if the rule's remote address resides in one of the clouds create a vpn gateway.

		// get the VPC of the rule's target
		remoteVPC, err := getRemoteVPC(ibmRule.Remote, rInfo.ResourceGroupName)
		if err != nil {
			return nil, err
		}
		// if the remote resides inside an invisinets VPC that isn't the request VM's VPC, connect them
		if remoteVPC != nil && remoteVPC.ID != *requestVPCData.ID {
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
			return nil, err
		}
		_, err = cloudClient.GetUniqueSGRules(sgRules, rulesHashValues)
		if err != nil {
			return nil, err
		}
		// compute hash value of rules, disregarding the ID field.
		ruleHashValue, err := ibmCommon.GetStructHash(ibmRule, []string{"ID"})
		if err != nil {
			return nil, err
		}
		// avoid adding duplicate rules (when hash values match)
		if _, ruleExists := rulesHashValues[ruleHashValue]; !ruleExists {
			err := cloudClient.AddSecurityGroupRule(ibmRule)
			if err != nil {
				return nil, err
			}
			utils.Log.Printf("attached rule %+v", ibmRule)
		} else {
			utils.Log.Printf("rule %+v already exists for security group ID %v", ibmRule, requestSGID)
		}
	}
	return &invisinetspb.AddPermitListRulesResponse{}, nil
}

// DeletePermitListRules deletes security group rules matching the attributes of the rules contained in the relevant Security group
func (s *ibmPluginServer) DeletePermitListRules(ctx context.Context, req *invisinetspb.DeletePermitListRulesRequest) (*invisinetspb.DeletePermitListRulesResponse, error) {
	rInfo, err := getResourceIDInfo(req.Resource)
	if err != nil {
		return nil, err
	}
	region, err := ibmCommon.ZoneToRegion(rInfo.Zone)
	if err != nil {
		return nil, err
	}

	cloudClient, err := s.setupCloudClient(rInfo.ResourceGroupName, region)
	if err != nil {
		return nil, err
	}

	// verify specified instance match the specified namespace
	if isInNamespace, err := cloudClient.IsInstanceInNamespace(
		rInfo.ResourceID, req.Namespace, region); !isInNamespace || err != nil {
		return nil, fmt.Errorf("Specified instance: %v doesn't exist in namespace: %v.",
			rInfo.ResourceID, req.Namespace)
	}

	// Get the VM ID from the resource ID (typically refers to VM Name)
	vmData, err := cloudClient.GetInstanceData(rInfo.ResourceID)
	if err != nil {
		return nil, err
	}
	vmID := *vmData.ID

	invisinetsSgsData, err := cloudClient.GetInvisinetsTaggedResources(sdk.SG, []string{vmID}, sdk.ResourceQuery{Region: region})
	if err != nil {
		return nil, err
	}
	if len(invisinetsSgsData) == 0 {
		return nil, fmt.Errorf("no security groups were found for VM %v", rInfo.ResourceID)
	}
	// assuming up to a single invisinets subnet can exist per zone
	vmInvisinetsSgID := invisinetsSgsData[0].ID

	for _, ruleID := range req.RuleNames {
		err = cloudClient.DeleteSecurityGroupRule(vmInvisinetsSgID, ruleID)
		if err != nil {
			return nil, err
		}
		utils.Log.Printf("Deleted rule %v", ruleID)
	}
	return &invisinetspb.DeletePermitListRulesResponse{}, nil

}

// Setup starts up the plugin server and stores the frontend server address.
func Setup(port int) {
	pluginServerAddress := "localhost"
	lis, err := net.Listen("tcp", fmt.Sprintf("%v:%d", pluginServerAddress, port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	ibmServer := ibmPluginServer{
		cloudClient:        make(map[string]*sdk.CloudClient),
		frontendServerAddr: fmt.Sprintf("%v:%v", FrontendServerAddr, port),
	}
	invisinetspb.RegisterCloudPluginServer(grpcServer, &ibmServer)
	fmt.Printf("Starting plugin server on: %v:%v", pluginServerAddress, port)
	fmt.Printf("Frontend Server address: %s", FrontendServerAddr)
	err = grpcServer.Serve(lis)
	if err != nil {
		fmt.Println(err.Error())
	}
}
