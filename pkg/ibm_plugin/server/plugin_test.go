package ibm

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"testing"

	utils "github.com/NetSys/invisinets/pkg/utils"

	"github.com/NetSys/invisinets/pkg/fake"
	sdk "github.com/NetSys/invisinets/pkg/ibm_plugin/sdk"
	"github.com/NetSys/invisinets/pkg/invisinetspb"

	"github.com/stretchr/testify/require"
)

// test cli flags
var vmID string   // (optional flag) existing invisinets VM ID.
var region string // (optional flag) existing invisinets VM ID.
var zone string   // (optional flag) zone to launch a VM in.
var delVPC bool   // (optional flag) if set to true cleans resources after test.

// permit list example
var premitList1 []*invisinetspb.PermitListRule = []*invisinetspb.PermitListRule{
	//TCP protocol rules
	{
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   443,
		DstPort:   443,
		Protocol:  6,
		Targets:   []string{"10.0.0.0/18"},
	},
	{
		Direction: invisinetspb.Direction_OUTBOUND,
		SrcPort:   8080,
		DstPort:   8080,
		Protocol:  6,
		Targets:   []string{"10.0.128.12", "10.0.128.13"},
	},
	//All protocol rules
	{
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   -1,
		DstPort:   -1,
		Protocol:  -1,
		Targets:   []string{"10.0.64.0/22", "10.0.64.0/24"},
	},
	{
		Direction: invisinetspb.Direction_OUTBOUND,
		SrcPort:   -1,
		DstPort:   -1,
		Protocol:  -1,
		Targets:   []string{"10.0.64.1"},
	},
}

func init() {
	flag.StringVar(&vmID, "vmID", "", "Existing invisinets VM ID")
	flag.StringVar(&region, "region", "", "IBM region")
	flag.StringVar(&zone, "zone", "", "IBM zone")
	flag.BoolVar(&delVPC, "delVPC", false, "if specified, terminates vpc after tests end")
}

// to terminate the created vpc specify -delVPC.
// to launch VM in a specific zone specify -zone=<zoneName>, e.g.:
// go test -run TestCreateResourceVMNewDeployment -delVPC -zone=eu-de-1
// NOTE: use sdk's TestTerminateVPC to delete the VPC post run.
func TestCreateResourceVMNewDeployment(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeControllerServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}

	if zone == "" {
		println("(TestGetPermitList skipped - missing argument: zone)")
		t.Skip("TestCreateResourceVMExsitingVPC skipped - missing arguments")
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
		err = s.cloudClient.TerminateVPC(vpcID)
		require.NoError(t, err)
	}
}

// usage: go test -run TestGetPermitList -region=<value> -vmID=<value>
func TestGetPermitList(t *testing.T) {
	if vmID == "" || region == "" {
		println("(TestGetPermitList skipped - missing arguments)")
		t.Skip("TestGetPermitList skipped - missing arguments")
	}

	s := &ibmPluginServer{}
	resourceID := &invisinetspb.ResourceID{
		Id: fmt.Sprintf("/ResourceGroupID/NOTUSED/Region/%v/ResourceID/%v", region, vmID),
	}
	resp, err := s.GetPermitList(context.Background(), resourceID)
	require.NoError(t, err)
	require.NotNil(t, resp)

	b, err := json.MarshalIndent(resp, "", "  ")
	require.NoError(t, err)
	// Note: direction:0(inbound) will not be printed.
	utils.Log.Printf("Permit rules of instance %v are:\n%v", vmID, string(b))

}

// usage: go test -run TestAddPermitListRules -region=<value> -vmID=<value>
func TestAddPermitListRules(t *testing.T) {
	if vmID == "" || region == "" {
		println("(TestGetPermitList skipped - missing arguments)")
		t.Skip("TestAddPermitListRules skipped - missing arguments")
	}

	permitList := &invisinetspb.PermitList{
		AssociatedResource: fmt.Sprintf("/ResourceGroupID/NOTUSED/Region/%v/ResourceID/%v", region, vmID),
		Rules:              premitList1,
	}

	s := &ibmPluginServer{}

	resp, err := s.AddPermitListRules(context.Background(), permitList)
	require.NoError(t, err)
	require.NotNil(t, resp)

	fmt.Printf("respond: %v", resp)
}

// usage: go test -run TestDeletePermitListRules -region=<value> -vmID=<value>
func TestDeletePermitListRules(t *testing.T) {
	if vmID == "" || region == "" {
		println("(TestGetPermitList skipped - missing arguments)")
		t.Skip("TestCreateResourceVMExsitingVPC skipped - missing arguments")
	}

	permitList := &invisinetspb.PermitList{
		AssociatedResource: fmt.Sprintf("/ResourceGroupID/NOTUSED/Region/%v/ResourceID/%v", region, vmID),
		Rules:              premitList1,
	}

	s := &ibmPluginServer{}

	resp, err := s.DeletePermitListRules(context.Background(), permitList)
	require.NoError(t, err)
	require.NotNil(t, resp)

	fmt.Printf("respond: %v", resp)
}
