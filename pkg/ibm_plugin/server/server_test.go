package ibm

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"testing"

	"github.com/NetSys/invisinets/pkg/fake"
	sdk "github.com/NetSys/invisinets/pkg/ibm_plugin/sdk"
	"github.com/NetSys/invisinets/pkg/invisinetspb"

	"github.com/stretchr/testify/require"
)

var vmID string   // (optional flag) existing invisinets VM ID.
var region string // (optional flag) existing invisinets VM ID.
var zone string   // (optional flag) zone to launch a VM in.
var delVPC bool   // (optional flag) if set to true cleans resources after test.

func init() {
	flag.StringVar(&vmID, "vmID", "", "Existing invisinets VM ID")
	flag.StringVar(&region, "region", "", "IBM region")
	flag.StringVar(&zone, "zone", "", "IBM zone")
	flag.BoolVar(&delVPC, "delVPC", false, "if specified, terminates vpc after tests ends")
}

// to terminate the created vpc specify -delVPC.
// to launch VM in a specific zone specify -zone=<zoneName>, e.g.:
// go test -run TestCreateResourceVMNewDeployment -delVPC -zone=eu-de-1
func TestCreateResourceVMNewDeployment(t *testing.T) {

	fakeControllerServerAddr, err := fake.SetupFakeControllerServer()
	if err != nil {
		t.Fatal(err)
	}

	// choose default zone if not specified
	if zone == "" {
		zone = "us-east-1"
	}

	instanceData := InstanceData{
		Zone:    zone,
		Profile: string(sdk.LowCPU),
		Name:    "",
	}

	s := &ibmPluginServer{
		frontendServerAddr: fakeControllerServerAddr}
	description, err := json.Marshal(instanceData)
	require.NoError(t, err)

	resource := &invisinetspb.ResourceDescription{Description: description}
	resp, err := s.CreateResource(context.Background(), resource)
	if err != nil {
		println(err)
	}
	require.NoError(t, err)
	require.NotNil(t, resp)

	if delVPC {
		vpcID, err := s.cloudClient.VmID2VpcID(resp.UpdatedResource.Id)
		require.NoError(t, err)
		defer s.cloudClient.TerminateVPC(vpcID)
	}
}

// usage: go test -run TestGetPermitList -region=<value> -vmID=<value>
func TestGetPermitList(t *testing.T) {
	if vmID == "" {
		println("(TestGetPermitList skipped - missing arguments)")
		t.Skip("TestCreateResourceVMExsitingVPC skipped - missing arguments")
	}

	// choose default region if not specified
	if region == "" {
		region = "us-east"
	}

	s := &ibmPluginServer{}
	resourceID := &invisinetspb.ResourceID{
		Id: fmt.Sprintf("/ResourceGroupID/NOTUSED/Region/%v/ResourceID/%v", region, vmID),
	}
	resp, err := s.GetPermitList(context.Background(), resourceID)
	require.NoError(t, err)
	require.NotNil(t, resp)
	fmt.Printf("Permit rules of instance %v are: %v", vmID, resp)
}
