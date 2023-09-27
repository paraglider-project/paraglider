package ibm

import (
	"context"
	"encoding/json"
	"flag"
	"testing"

	"github.com/NetSys/invisinets/pkg/fake"
	sdk "github.com/NetSys/invisinets/pkg/ibm_plugin/sdk"
	"github.com/NetSys/invisinets/pkg/invisinetspb"

	"github.com/stretchr/testify/require"
)

var zone string // (optional flag) zone to launch a VM in.
var delVPC bool // (optional flag) if set to true cleans resources after test.

func init() {
	flag.StringVar(&zone, "zone", "", "zone to create a VM in")
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
		frontendServerAddr:fakeControllerServerAddr}
	description, err := json.Marshal(instanceData)
	require.NoError(t, err)

	resource := &invisinetspb.ResourceDescription{Description: description}
	resp, err := s.CreateResource(context.Background(), resource)
	if err != nil {
		println(err)
	}
	require.NoError(t, err)

	if delVPC {
		vpcID, err := s.cloudClient.VmID2VpcID(resp.UpdatedResource.Id)
		require.NoError(t, err)
		defer s.cloudClient.TerminateVPC(vpcID)
	}
	require.NoError(t, err)
	require.NotNil(t, resp)
}
