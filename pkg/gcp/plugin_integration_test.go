//go:build integration

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

package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/googleapi"
	"google.golang.org/protobuf/proto"
)

type teardownInfo struct {
	project            string
	insertInstanceReqs []*computepb.InsertInstanceRequest
}

// Max lengths for random resource name generation
const vmNameMaxLength = 63

// Generates random VM name to ensure parallel runs of these tests don't run into duplicate resource issues
func generateRandomVMName() string {
	vmName := "vm-invisinets-test-" + uuid.New().String()
	if len(vmName) > vmNameMaxLength {
		vmName = vmName[:vmNameMaxLength]
	}
	return vmName
}

// Cleans up any resources that were created
// If you got a panic while the tests ran, you may need to manually clean up resources, which is most easily done through the console.
// 1. Delete VMs (https://cloud.google.com/compute/docs/instances/deleting-instance).
// 2. Delete VPC (https://cloud.google.com/vpc/docs/create-modify-vpc-networks#deleting_a_network). Doing this in the console should delete any associated firewalls and subnets.
func teardownIntegrationTest(teardownInfo *teardownInfo) {
	// Delete VMs
	instancesClient, err := compute.NewInstancesRESTClient(context.Background())
	if err != nil {
		panic(fmt.Sprintf("Error while creating client (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
	}
	for _, insertInstanceReq := range teardownInfo.insertInstanceReqs {
		deleteInstanceReq := &computepb.DeleteInstanceRequest{
			Project:  insertInstanceReq.Project,
			Zone:     insertInstanceReq.Zone,
			Instance: *insertInstanceReq.InstanceResource.Name,
		}
		deleteInstanceReqOp, err := instancesClient.Delete(context.Background(), deleteInstanceReq)
		if err != nil {
			var e *googleapi.Error
			if ok := errors.As(err, &e); !ok || e.Code != http.StatusNotFound {
				// Ignore 404 errors since resource may not have been created due to an error while running the test
				panic(fmt.Sprintf("Error on delete instance request (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
			}
		} else {
			err = deleteInstanceReqOp.Wait(context.Background())
			if err != nil {
				panic(fmt.Sprintf("Error while waiting on delete instance op (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
			}
		}
	}

	// Delete subnetworks
	networksClient, err := compute.NewNetworksRESTClient(context.Background())
	if err != nil {
		panic(fmt.Sprintf("Error while creating networks client (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
	}
	subnetworksClient, err := compute.NewSubnetworksRESTClient(context.Background())
	if err != nil {
		panic(fmt.Sprintf("Error while creating subnetworks client (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
	}
	deletedSubnetworkRegions := map[string]bool{}
	for _, insertInstanceReq := range teardownInfo.insertInstanceReqs {
		region := insertInstanceReq.Zone[:strings.LastIndex(insertInstanceReq.Zone, "-")]
		if !deletedSubnetworkRegions[region] {
			deleteSubnetworkReq := &computepb.DeleteSubnetworkRequest{
				Project:    teardownInfo.project,
				Region:     region,
				Subnetwork: getGCPSubnetworkName(region),
			}
			deleteSubnetworkOp, err := subnetworksClient.Delete(context.Background(), deleteSubnetworkReq)
			if err != nil {
				var e *googleapi.Error
				if ok := errors.As(err, &e); !ok || e.Code != http.StatusNotFound {
					// Ignore 404 errors since resource may not have been created due to an error while running the test
					panic(fmt.Sprintf("Error on delete subnetwork request (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
				}
			} else {
				err = deleteSubnetworkOp.Wait(context.Background())
				if err != nil {
					panic(fmt.Sprintf("Error while waiting on delete subnetwork op (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
				}
			}
			deletedSubnetworkRegions[region] = true
		}
	}

	// Delete firewalls
	getEffectiveFirewallsReq := &computepb.GetEffectiveFirewallsNetworkRequest{
		Project: teardownInfo.project,
		Network: vpcName,
	}
	getEffectiveFirewallsResp, err := networksClient.GetEffectiveFirewalls(context.Background(), getEffectiveFirewallsReq)
	if err != nil {
		panic(fmt.Sprintf("Error while getting firewalls (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
	}
	firewallsClient, err := compute.NewFirewallsRESTClient(context.Background())
	if err != nil {
		panic(fmt.Sprintf("Error while creating firewalls client (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
	}
	for _, firewall := range getEffectiveFirewallsResp.Firewalls {
		deleteFirewallReq := &computepb.DeleteFirewallRequest{
			Firewall: *firewall.Name,
			Project:  teardownInfo.project,
		}
		deleteFirewallOp, err := firewallsClient.Delete(context.Background(), deleteFirewallReq)
		if err != nil {
			var e *googleapi.Error
			if ok := errors.As(err, &e); !ok || e.Code != http.StatusNotFound {
				// Ignore 404 errors since resource may not have been created due to an error while running the test
				panic(fmt.Sprintf("Error on delete firewall request (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
			}
		} else {
			err = deleteFirewallOp.Wait(context.Background())
			if err != nil {
				panic(fmt.Sprintf("Error while waiting on delete firewall op (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
			}
		}
	}

	// Delete VPC
	deleteNetworkReq := &computepb.DeleteNetworkRequest{
		Project: teardownInfo.project,
		Network: vpcName,
	}
	deleteNetworkOp, err := networksClient.Delete(context.Background(), deleteNetworkReq)
	if err != nil {
		var e *googleapi.Error
		if ok := errors.As(err, &e); !ok || e.Code != http.StatusNotFound {
			// Ignore 404 errors since resource may not have been created due to an error while running the test
			panic(fmt.Sprintf("Error on delete subnetwork request (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
		}
	} else {
		err = deleteNetworkOp.Wait(context.Background())
		if err != nil {
			panic(fmt.Sprintf("Error while waiting on delete network op (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
		}
	}
}

// Tests creating two vms in separate regions and basic add/delete/get permit list functionality
func TestIntegration(t *testing.T) {
	// Setup
	project := os.Getenv("INVISINETS_GCP_PROJECT")
	if project == "" {
		panic("INVISINETS_GCP_PROJECT must be set")
	}
	s := &GCPPluginServer{}

	// Teardown
	teardownInfo := &teardownInfo{
		project:            project,
		insertInstanceReqs: make([]*computepb.InsertInstanceRequest, 0),
	}
	defer teardownIntegrationTest(teardownInfo)

	// Disk setting to be used across VM creation
	var disks = []*computepb.AttachedDisk{
		{
			InitializeParams: &computepb.AttachedDiskInitializeParams{
				DiskSizeGb:  proto.Int64(10),
				SourceImage: proto.String("projects/debian-cloud/global/images/family/debian-10"),
			},
			AutoDelete: proto.Bool(true),
			Boot:       proto.Bool(true),
			Type:       proto.String(computepb.AttachedDisk_PERSISTENT.String()),
		},
	}

	// Create VM in a clean state (i.e. no VPC or subnet)
	vm1Name := generateRandomVMName()
	insertInstanceReq1 := &computepb.InsertInstanceRequest{
		Project: project,
		Zone:    "us-west1-a",
		InstanceResource: &computepb.Instance{
			Name:        proto.String(vm1Name),
			MachineType: proto.String("zones/us-west1-a/machineTypes/f1-micro"),
			Disks:       disks,
		},
	}
	teardownInfo.insertInstanceReqs = append(teardownInfo.insertInstanceReqs, insertInstanceReq1)
	insertInstanceReq1Bytes, err := json.Marshal(insertInstanceReq1)
	if err != nil {
		t.Fatal(err)
	}
	resourceDescription1 := &invisinetspb.ResourceDescription{
		Description: insertInstanceReq1Bytes,
	}
	createResource1Resp, err := s.CreateResource(
		context.Background(),
		resourceDescription1,
	)
	require.NoError(t, err)
	require.NotNil(t, createResource1Resp)
	assert.True(t, createResource1Resp.Success)

	// Create VM in different region (i.e. requires new subnet to be created)
	vm2Name := generateRandomVMName()
	insertInstanceReq2 := &computepb.InsertInstanceRequest{
		Project: project,
		Zone:    "us-east1-b",
		InstanceResource: &computepb.Instance{
			Name:        proto.String(vm2Name),
			MachineType: proto.String("zones/us-east1-b/machineTypes/f1-micro"),
			Disks:       disks,
		},
	}
	teardownInfo.insertInstanceReqs = append(teardownInfo.insertInstanceReqs, insertInstanceReq2)
	insertInstanceReq2Bytes, err := json.Marshal(insertInstanceReq2)
	if err != nil {
		t.Fatal(err)
	}
	resourceDescription2 := &invisinetspb.ResourceDescription{
		Description: insertInstanceReq2Bytes,
	}
	createResource2Resp, err := s.CreateResource(
		context.Background(),
		resourceDescription2,
	)
	require.NoError(t, err)
	require.NotNil(t, createResource2Resp)
	assert.True(t, createResource2Resp.Success)

	// Check VPC and subnetworks
	networksClient, err := compute.NewNetworksRESTClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	getNetworkReq := &computepb.GetNetworkRequest{
		Network: vpcName,
		Project: project,
	}
	getNetworkResp, err := networksClient.Get(context.Background(), getNetworkReq)
	require.NoError(t, err)
	require.NotNil(t, getNetworkResp)
	subnetworks := make([]string, len(getNetworkResp.Subnetworks))
	for i, subnetURL := range getNetworkResp.Subnetworks {
		subnetworks[i] = subnetURL[strings.LastIndex(subnetURL, "/")+1:]
	}
	assert.ElementsMatch(
		t,
		[]string{getGCPSubnetworkName("us-west1"), getGCPSubnetworkName("us-east1")},
		subnetworks,
	)

	resourceId := "projects/" + project + "/zones/" + insertInstanceReq1.Zone + "/instances/" + *insertInstanceReq1.InstanceResource.Name

	permitList := &invisinetspb.PermitList{
		AssociatedResource: resourceId,
		Rules: []*invisinetspb.PermitListRule{
			{
				Direction: invisinetspb.Direction_INBOUND,
				DstPort:   443,
				Protocol:  6,
				Tag:       []string{"10.162.162.0/24"},
			},
		},
	}
	addPermitListRulesResp, err := s.AddPermitListRules(context.Background(), permitList)
	require.NoError(t, err)
	require.NotNil(t, addPermitListRulesResp)
	assert.True(t, addPermitListRulesResp.Success)

	getPermitListAfterAddResp, err := s.GetPermitList(context.Background(), &invisinetspb.ResourceID{Id: resourceId})
	require.NoError(t, err)
	require.NotNil(t, getPermitListAfterAddResp)
	assert.Equal(t, permitList.AssociatedResource, getPermitListAfterAddResp.AssociatedResource)
	assert.ElementsMatch(t, permitList.Rules, getPermitListAfterAddResp.Rules)

	deletePermitListRulesResp, err := s.DeletePermitListRules(context.Background(), permitList)
	require.NoError(t, err)
	require.NotNil(t, deletePermitListRulesResp)
	assert.True(t, deletePermitListRulesResp.Success)

	getPermitListAfterDeleteResp, err := s.GetPermitList(context.Background(), &invisinetspb.ResourceID{Id: resourceId})
	require.NoError(t, err)
	require.NotNil(t, getPermitListAfterDeleteResp)
	assert.Equal(t, permitList.AssociatedResource, getPermitListAfterDeleteResp.AssociatedResource)
	assert.Empty(t, getPermitListAfterDeleteResp.Rules)
}
