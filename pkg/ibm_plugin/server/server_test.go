package ibm

import (
	"context"
	"encoding/json"
	"flag"
	"testing"

	sdk "github.com/NetSys/invisinets/pkg/ibm_plugin/sdk"
	"github.com/NetSys/invisinets/pkg/invisinetspb"

	"github.com/stretchr/testify/require"
)

var vpcID string
var zone string

func init() {
	flag.StringVar(&vpcID, "vpcID", "", "vpc id to create a resource in")
	flag.StringVar(&zone, "zone", "", "zone to create a VM in")
}

func TestCreateResourceVMNewDeployment(t *testing.T) {
	// can manually be set to "", or different value
	addressSpace := "10.241.1.0/24"

	instanceData := InstanceFields{Zone: "us-east-1"}

	s := &ibmPluginServer{}
	description, err := json.Marshal(instanceData)
	require.NoError(t, err)

	resource := &invisinetspb.ResourceDescription{Description: description, AddressSpace: addressSpace}
	resp, err := s.CreateResource(context.Background(), resource)

	// clean resource if created during this test
	if instanceData.VpcID == "" {
		defer s.cloudClient.TerminateVPC(s.cloudClient.VmID2VpcID(resp.UpdatedResource.Id))
	}
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestCreateResourceVMExsitingVPC(t *testing.T) {
	if vpcID == "" || zone == "" {
		println("(TestCreateResourceVMExsitingVPC skipped - missing arguments)")
		t.Skip("TestCreateResourceVMExsitingVPC skipped - missing arguments")
	}
	// can manually be set to "", or different value
	addressSpace := "10.241.1.0/24"

	instanceData := InstanceFields{
		VpcID:        vpcID,
		SubnetID:     "",
		AddressSpace: addressSpace,
		Profile:      string(sdk.LowCPU),
		Zone:         zone,
		Name:         "",
	}

	s := &ibmPluginServer{}
	description, err := json.Marshal(instanceData)
	require.NoError(t, err)

	resource := &invisinetspb.ResourceDescription{Description: description, AddressSpace: addressSpace}
	resp, err := s.CreateResource(context.Background(), resource)
	require.NoError(t, err)
	require.NotNil(t, resp)
}
