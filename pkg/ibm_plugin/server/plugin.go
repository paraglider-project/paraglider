package ibm

import (
	"context"
	"fmt"
	"net"
	"os"

	utils "github.com/NetSys/invisinets/pkg/utils"

	sdk "github.com/NetSys/invisinets/pkg/ibm_plugin/sdk"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type ibmPluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
	cloudClient        *sdk.IBMCloudClient
	frontendServerAddr string
}

func (s *ibmPluginServer) setupCloudClient(region string) error {
	client, err := sdk.NewIBMCloudClient(region)
	if err != nil {
		utils.Log.Println("Failed to set up IBM clients with error:", err)
		return err
	}
	s.cloudClient = client
	return nil
}

// Creates the specified resource. Currently only supports instance creation.
// Default instance profile is 2CPU, 8GB RAM, unless specified.
// Default instance name will be auto-generated unless specified.
func (s *ibmPluginServer) CreateResource(c context.Context, resourceDesc *invisinetspb.ResourceDescription) (*invisinetspb.BasicResponse, error) {
	var vpcID string

	vmFields, err := getInstanceData(resourceDesc)
	if err != nil {
		return nil, err
	}

	region, err := sdk.Zone2Region(vmFields.Zone)
	if err != nil {
		utils.Log.Println("Failed to convert zone to region:", region)
		return nil, err
	}
	err = s.setupCloudClient(region)
	if err != nil {
		return nil, err
	}
	/* TODO: Future support in multiple deployments and multiple vpcs
	in single region will require adding deployment ID as a tag
	*/
	vpcIDs, err := s.cloudClient.GetInvisinetsTaggedResources(sdk.VPC, nil,
		sdk.ResourceQuery{Region: region})
	if err != nil {
		return nil, err
	}

	// use existing invisinets VPC or create a new one
	if len(vpcIDs) != 0 {
		// currently assuming a single VPC per region
		vpcID = vpcIDs[0]
		utils.Log.Printf("Reusing invisinets VPC with ID: %v in region %v", vpcID, region)
	} else {
		conn, err := grpc.Dial(s.frontendServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		client := invisinetspb.NewControllerClient(conn)
		response, err := client.FindUnusedAddressSpace(context.Background(), &invisinetspb.Empty{})
		if err != nil {
			return nil, err
		}
		// create a vpc with a subnet in each zone
		vpc, err := s.cloudClient.CreateVpc("", response.Address)
		if err != nil {
			return nil, err
		}
		vpcID = *vpc.ID
	}

	// Retrieving an invisinets subnet that's tagged with the above VPC ID in the specified zone.
	requiredTags := []string{vpcID}
	subnetsIDs, err := s.cloudClient.GetInvisinetsTaggedResources(sdk.SUBNET, requiredTags,
		sdk.ResourceQuery{Zone: vmFields.Zone})
	if err != nil {
		return nil, err
	}
	if len(subnetsIDs) == 0 {
		// No invisinets subnets were found matching vpc and zone
		return nil, fmt.Errorf("invisinets subnet wasn't found")
	}
	// Assuming one invisinets subnet per zone
	subnetID := subnetsIDs[0]

	vm, err := s.cloudClient.CreateVM(vpcID, subnetID,
		vmFields.Zone, vmFields.Name, vmFields.Profile)
	if err != nil {
		return nil, err
	}
	return &invisinetspb.BasicResponse{Success: true, Message: "successfully created VM",
		UpdatedResource: &invisinetspb.ResourceID{Id: *vm.ID}}, nil
}

// returns a list of address spaces used by either user's or invisinets' sunbets,
// for each invisinets vpc.
func (s *ibmPluginServer) GetUsedAddressSpaces(ctx context.Context, deployment *invisinetspb.InvisinetsDeployment) (*invisinetspb.AddressSpaceList, error) {
	var invisinetsAddressSpaces []string
	err := s.setupCloudClient("")
	if err != nil {
		return nil, err
	}
	// get all VPCs in the deployment.
	// TODO future multi deployment support will require sending deployment id as tag, currently using static tag.
	deploymentVpcIDs, err := s.cloudClient.GetInvisinetsTaggedResources(sdk.VPC, nil, sdk.ResourceQuery{})
	if err != nil {
		return nil, err
	}
	// for each vpc, collect the address space of all subnets, including users'.
	for _, vpcID := range deploymentVpcIDs {
		subnets, err := s.cloudClient.GetSubnetsInVPC(vpcID)
		if err != nil {
			return nil, err
		}
		for _, subnet := range subnets {
			invisinetsAddressSpaces = append(invisinetsAddressSpaces, *subnet.Ipv4CIDRBlock)
		}
	}
	return &invisinetspb.AddressSpaceList{AddressSpaces: invisinetsAddressSpaces}, nil
}

// returns security rules of security groups associated with the specified instance.
func (s *ibmPluginServer) GetPermitList(ctx context.Context, resourceID *invisinetspb.ResourceID) (*invisinetspb.PermitList, error) {
	permitList := &invisinetspb.PermitList{
		AssociatedResource: resourceID.Id,
		Rules:              []*invisinetspb.PermitListRule{},
	}
	resourceIDInfo, err := getResourceIDInfo(resourceID.Id)
	if err != nil {
		return nil, err
	}
	region, vmID := resourceIDInfo.Region, resourceIDInfo.ResourceID
	err = s.setupCloudClient(region)
	if err != nil {
		return nil, err
	}

	securityGroups, err := s.cloudClient.GetSecurityGroupsOfVM(vmID)
	if err != nil {
		return nil, err
	}
	var sgsRules []sdk.SecurityGroupRule
	rulesHashValues := map[int64]bool{}
	// collect rules from all security groups attached to VM.
	for _, sgID := range securityGroups {
		sgRules, err := s.cloudClient.GetSecurityRulesOfSG(sgID)
		if err != nil {
			return nil, err
		}
		// filter away duplicate rules
		rules, err := s.getUniqueSgRules(sgRules, rulesHashValues)
		if err != nil {
			return nil, err
		}
		// append new rules to result
		sgsRules = append(sgsRules, rules...)
	}
	invisinetsRules, err := sgRules2InvisinetsRules(sgsRules)
	if err != nil {
		return nil, err
	}

	permitList.Rules = invisinetsRules
	return permitList, nil
}

// Attaches SG rules to the specified instance in PermitList.AssociatedResource.
func (s *ibmPluginServer) AddPermitListRules(ctx context.Context, pl *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	// var vmInvisinetsSgID string // security group to add rules to
	var subnetsCIDRs []string
	resourceIDInfo, err := getResourceIDInfo(pl.AssociatedResource)
	if err != nil {
		return nil, err
	}
	region, vmID := resourceIDInfo.Region, resourceIDInfo.ResourceID
	err = s.setupCloudClient(region)
	if err != nil {
		return nil, err
	}

	invisinetsSgIDs, err := s.cloudClient.GetInvisinetsTaggedResources(sdk.SG, []string{vmID}, sdk.ResourceQuery{Region: region})
	if err != nil {
		return nil, err
	}
	if len(invisinetsSgIDs) == 0 {
		return nil, fmt.Errorf("no security groups were found for VM %v", vmID)
	}
	// assuming up to a single invisinets subnet can exist per zone
	vmInvisinetsSgID := invisinetsSgIDs[0]

	vpcID, err := s.cloudClient.VmID2VpcID(vmID)
	if err != nil {
		return nil, err
	}
	// get subnets in the VM's VPC
	invisinetsSubnetsOfVpc, err := s.cloudClient.GetInvisinetsTaggedResources(sdk.SUBNET, []string{vpcID}, sdk.ResourceQuery{})
	if err != nil {
		return nil, err
	}
	// aggregate the address spaces of subnets in the VM's VPC
	for _, invSubnet := range invisinetsSubnetsOfVpc {
		cidr, err := s.cloudClient.GetSubnetCidr(invSubnet)
		if err != nil {
			return nil, err
		}
		subnetsCIDRs = append(subnetsCIDRs, cidr)
	}

	rulesHashValues := make(map[int64]bool)
	// get current rules in SG and record their hash values
	sgRules, err := s.cloudClient.GetSecurityRulesOfSG(vmInvisinetsSgID)
	if err != nil {
		return nil, err
	}
	_, err = s.getUniqueSgRules(sgRules, rulesHashValues)
	if err != nil {
		return nil, err
	}

	// translate invisinets rules to IBM rules to compare hash values with current rules.
	ibmRulesToAdd, err := invisinetsRules2IbmRules(vmInvisinetsSgID, pl.Rules)
	if err != nil {
		return nil, err
	}

	for _, ibmRule := range ibmRulesToAdd {
		isSubset := false
		// checks if the rule's remote IP/CIDR is within any of the VPC's subnets
		for _, subnetSpace := range subnetsCIDRs {
			isSubset, err = sdk.IsRemoteInCidr(ibmRule.Remote, subnetSpace)
			if err != nil {
				return nil, err
			}
			if isSubset {
				// remote is inside the instance's VPC
				break
			}
		}
		// the rule's remote resides in a different VPC, connect the VPCs.
		if !isSubset {
			return nil, fmt.Errorf(`rule's remote "%v" is outside of the resource's VPC. `+
				`Inter VPC connectivity isn't currently supported.`, ibmRule.Remote)
			/*TODO:
			   remote isn't from within the VM's VPC.
			1. find invisinets subnets that have cidr blocks that this remote is a part of.
				 if none were found return err.
			2. find the vpc of the subnet.
			3. connect vpcs via transit gateway.
			*/
		}
		ruleHashValue, err := getStructHash(ibmRule, []string{"ID"})
		if err != nil {
			return nil, err
		}
		if _, ruleExists := rulesHashValues[int64(ruleHashValue)]; !ruleExists {
			err := s.cloudClient.AddSecurityGroupRule(ibmRule)
			if err != nil {
				return nil, err
			}
			utils.Log.Printf("attached rule %+v", ibmRule)
		}
	}
	return &invisinetspb.BasicResponse{Success: true, Message: "successfully attached specified rules to VM's security group"}, nil
}

// deletes security group rules matching the attributes of the rules contained in the relevant Security group
func (s *ibmPluginServer) DeletePermitListRules(ctx context.Context, pl *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	resourceIDInfo, err := getResourceIDInfo(pl.AssociatedResource)
	if err != nil {
		return nil, err
	}
	region, vmID := resourceIDInfo.Region, resourceIDInfo.ResourceID
	err = s.setupCloudClient(region)
	if err != nil {
		return nil, err
	}

	invisinetsSgIDs, err := s.cloudClient.GetInvisinetsTaggedResources(sdk.SG, []string{vmID}, sdk.ResourceQuery{Region: region})
	if err != nil {
		return nil, err
	}
	if len(invisinetsSgIDs) == 0 {
		return nil, fmt.Errorf("no security groups were found for VM %v", vmID)
	}
	// assuming up to a single invisinets subnet can exist per zone
	vmInvisinetsSgID := invisinetsSgIDs[0]

	ibmRulesToDelete, err := invisinetsRules2IbmRules(vmInvisinetsSgID, pl.Rules)
	if err != nil {
		return nil, err
	}
	rulesIDs, err := s.fetchRulesIDs(ibmRulesToDelete, vmInvisinetsSgID)
	if err != nil {
		return nil, err
	}
	for _, ruleID := range rulesIDs {
		err = s.cloudClient.DeleteSecurityGroupRule(vmInvisinetsSgID, ruleID)
		if err != nil {
			return nil, err
		}
		utils.Log.Printf("deleted rule %v", ruleID)
	}
	return &invisinetspb.BasicResponse{Success: true, Message: "successfully deleted rules from permit list"}, nil

}

func (s *ibmPluginServer) fetchRulesIDs(rules []sdk.SecurityGroupRule, sgID string) ([]string, error) {
	var rulesIDs []string
	sgRules, err := s.cloudClient.GetSecurityRulesOfSG(sgID)
	if err != nil {
		return nil, err
	}
	for _, sgRule := range sgRules {
		for _, rule := range rules {
			if sdk.AreStructsEqual(rule, sgRule, []string{"ID", "SgID"}) {
				rulesIDs = append(rulesIDs, sgRule.ID)
				// found matching rule, continue to the next sgRule
				break
			}
		}
	}
	return rulesIDs, nil
}

// return the specified rules without duplicates, while keeping the rules hash values updated for future use.
func (s *ibmPluginServer) getUniqueSgRules(rules []sdk.SecurityGroupRule, rulesHashValues map[int64]bool) ([]sdk.SecurityGroupRule, error) {
	var res []sdk.SecurityGroupRule
	for _, rule := range rules {
		// exclude unique field "ID" from hash calculation.
		ruleHashValue, err := getStructHash(rule, []string{"ID"})
		if err != nil {
			return nil, err
		}
		if _, ruleExists := rulesHashValues[int64(ruleHashValue)]; !ruleExists {
			res = append(res, rule)
			rulesHashValues[int64(ruleHashValue)] = true
		}
	}
	return res, nil
}

// starts up the plugin server and stores the frontend server address.
func Setup(port int, frontendAddress string) {
	pluginServerAddress := "localhost"
	lis, err := net.Listen("tcp", fmt.Sprintf("%v:%d", pluginServerAddress, port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	ibmServer := ibmPluginServer{
		cloudClient:        &sdk.IBMCloudClient{},
		frontendServerAddr: fmt.Sprintf("%v:%v", frontendAddress, port),
	}
	invisinetspb.RegisterCloudPluginServer(grpcServer, &ibmServer)
	fmt.Printf("Starting plugin server on: %v:%v\n", pluginServerAddress, port)
	fmt.Println("Received frontend Server address:", frontendAddress)
	err = grpcServer.Serve(lis)
	if err != nil {
		fmt.Println(err.Error())
	}
}
