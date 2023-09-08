package ibm

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	sdk "github.com/NetSys/invisinets/pkg/ibm_plugin/sdk"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
)

type ibmPluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
	cloudClient *sdk.IBMCloudClient
}

// InstanceFields is a temporary solution until invisinetspb.ResourceDescription.Description
// will be replaced with a concrete type
// using this struct instead of *vpcv1.Instance puts an emphasis
// on the relevant fields and makes the object easier to construct
type InstanceFields struct {
	VpcID        string `json:"vpc_id"`        // optional
	SubnetID     string `json:"subnet_id"`     // optional
	AddressSpace string `json:"address_space"` // optional`
	Profile      string `json:"profile"`       // optional
	Zone         string `json:"zone"`
	Name         string `json:"name"` // optional
}

// TODO edit ResourcePrefix to differentiate github workflows
// func init() {
// }

// Currently only supports VPC instance creation
func (s *ibmPluginServer) CreateResource(c context.Context, resourceDesc *invisinetspb.ResourceDescription) (*invisinetspb.BasicResponse, error) {
	vmFields := InstanceFields{}
	err := json.Unmarshal(resourceDesc.Description, &vmFields)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal resource description:%+v", err)
	}
	if vmFields.Zone == "" {
		log.Println("Missing mandatory zone field to launch a VM")
		return nil, err
	}
	region, err := sdk.Zone2Region(vmFields.Zone)
	if err != nil {
		log.Println("Invalid region:", region)
		return nil, err
	}
	s.cloudClient, err = sdk.NewIbmCloudClient(region)
	if err != nil {
		log.Println("Failed to set up IBM clients with error:", err)
		return nil, err
	}
	if vmFields.VpcID == "" {
		vpc, err := s.cloudClient.CreateVpc("")
		if err != nil {
			return nil, err
		}
		vmFields.VpcID = *vpc.ID
	}
	if vmFields.SubnetID == "" {
		subnet, err := s.cloudClient.CreateSubnet(vmFields.VpcID, vmFields.Zone, resourceDesc.AddressSpace)
		if err != nil {
			return nil, err
		}
		vmFields.SubnetID = *subnet.ID
	}
	vm, err := s.cloudClient.CreateDefaultVM(vmFields.VpcID, vmFields.SubnetID,
		vmFields.Zone, vmFields.Name, vmFields.Profile)
	if err != nil {
		return nil, err
	}
	return &invisinetspb.BasicResponse{Success: true, Message: "successfully created VM",
		UpdatedResource: &invisinetspb.ResourceID{Id: *vm.ID}}, nil
}
