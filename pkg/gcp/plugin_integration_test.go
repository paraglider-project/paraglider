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
	"fmt"
	"strings"
	"testing"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	networkmanagementpb "cloud.google.com/go/networkmanagement/apiv1/networkmanagementpb"
	fake "github.com/NetSys/invisinets/pkg/fake"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	utils "github.com/NetSys/invisinets/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests creating two vms in separate regions and basic add/delete/get permit list functionality
func TestIntegration(t *testing.T) {
	// Setup
	project := GetGcpProject()
	s := &GCPPluginServer{}
	_, fakeControllerServerAddr, err := fake.SetupFakeControllerServer(utils.GCP)
	if err != nil {
		t.Fatal(err)
	}
	FrontendServerAddr = fakeControllerServerAddr

	// Teardown
	teardownInfo := &GcpTestTeardownInfo{
		Project:            project,
		InsertInstanceReqs: make([]*computepb.InsertInstanceRequest, 0),
	}
	defer TeardownGcpTesting(teardownInfo)

	// Create VM in a clean state (i.e. no VPC or subnet)
	vm1Name := utils.GetGitHubRunPrefix() + "vm-invisinets-test-1"
	vm1Zone := "us-west1-a"
	insertInstanceReq1 := GetTestVmParameters(project, vm1Zone, vm1Name)
	teardownInfo.InsertInstanceReqs = append(teardownInfo.InsertInstanceReqs, insertInstanceReq1)
	insertInstanceReq1Bytes, err := json.Marshal(insertInstanceReq1)
	if err != nil {
		t.Fatal(err)
	}
	resourceDescription1 := &invisinetspb.ResourceDescription{Description: insertInstanceReq1Bytes}
	createResource1Resp, err := s.CreateResource(
		context.Background(),
		resourceDescription1,
	)
	require.NoError(t, err)
	require.NotNil(t, createResource1Resp)
	assert.True(t, createResource1Resp.Success)

	// Create VM in different region (i.e. requires new subnet to be created)
	vm2Name := utils.GetGitHubRunPrefix() + "vm-invisinets-test-2"
	vm2Zone := "us-east1-b"
	insertInstanceReq2 := GetTestVmParameters(project, vm2Zone, vm2Name)
	teardownInfo.InsertInstanceReqs = append(teardownInfo.InsertInstanceReqs, insertInstanceReq2)
	insertInstanceReq2Bytes, err := json.Marshal(insertInstanceReq2)
	if err != nil {
		t.Fatal(err)
	}
	resourceDescription2 := &invisinetspb.ResourceDescription{Description: insertInstanceReq2Bytes}
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

	// Add bidirectional PING permit list rules
	vm1Id := fmt.Sprintf("projects/%s/zones/%s/instances/%s", project, vm1Zone, vm1Name)
	vm2Id := fmt.Sprintf("projects/%s/zones/%s/instances/%s", project, vm2Zone, vm2Name)
	instancesClient, err := compute.NewInstancesRESTClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer instancesClient.Close()
	vm1Ip, err := GetInstanceIpAddress(project, vm1Zone, vm1Name)
	require.NoError(t, err)
	vm2Ip, err := GetInstanceIpAddress(project, vm2Zone, vm2Name)
	require.NoError(t, err)

	vmIds := []string{vm1Id, vm2Id}
	permitLists := [2]*invisinetspb.PermitList{
		{
			AssociatedResource: vm1Id,
			Rules: []*invisinetspb.PermitListRule{
				{
					Direction: invisinetspb.Direction_INBOUND,
					SrcPort:   -1,
					DstPort:   -1,
					Protocol:  1,
					Tag:       []string{vm2Ip},
				},
				{
					Direction: invisinetspb.Direction_OUTBOUND,
					DstPort:   -1,
					Protocol:  1,
					Tag:       []string{vm2Ip},
				},
			},
		},
		{
			AssociatedResource: vm2Id,
			Rules: []*invisinetspb.PermitListRule{
				{
					Direction: invisinetspb.Direction_INBOUND,
					SrcPort:   -1,
					DstPort:   -1,
					Protocol:  1,
					Tag:       []string{vm1Ip},
				},
				{
					Direction: invisinetspb.Direction_OUTBOUND,
					SrcPort:   -1,
					DstPort:   -1,
					Protocol:  1,
					Tag:       []string{vm1Ip},
				},
			},
		},
	}
	for i, vmId := range vmIds {
		permitList := permitLists[i]
		addPermitListRulesResp, err := s.AddPermitListRules(context.Background(), permitList)
		require.NoError(t, err)
		require.NotNil(t, addPermitListRulesResp)
		assert.True(t, addPermitListRulesResp.Success)

		getPermitListAfterAddResp, err := s.GetPermitList(context.Background(), &invisinetspb.ResourceID{Id: vmId})
		require.NoError(t, err)
		require.NotNil(t, getPermitListAfterAddResp)
		assert.Equal(t, permitList.AssociatedResource, getPermitListAfterAddResp.AssociatedResource)
		assert.ElementsMatch(t, permitList.Rules, getPermitListAfterAddResp.Rules)
	}

	// Connectivity tests that ping the two VMs
	// TODO @seankimkdy: NewReachabilityRESTClient causes errors when deleting connectivity tests
	vm1Endpoint := &networkmanagementpb.Endpoint{
		IpAddress: vm1Ip,
		Network:   "projects/" + project + "/" + GetVpcUri(),
		ProjectId: project,
	}
	vm2Endpoint := &networkmanagementpb.Endpoint{
		IpAddress: vm2Ip,
		Network:   "projects/" + project + "/" + GetVpcUri(),
		ProjectId: project,
	}

	// Run connectivity tests on both directions between vm1 and vm2
	RunPingConnectivityTest(t, project, "1to2", vm1Endpoint, vm2Endpoint)
	RunPingConnectivityTest(t, project, "2to1", vm2Endpoint, vm1Endpoint)

	// Delete permit lists
	for i, vmId := range vmIds {
		permitList := permitLists[i]
		deletePermitListRulesResp, err := s.DeletePermitListRules(context.Background(), permitList)
		require.NoError(t, err)
		require.NotNil(t, deletePermitListRulesResp)
		assert.True(t, deletePermitListRulesResp.Success)

		getPermitListAfterDeleteResp, err := s.GetPermitList(context.Background(), &invisinetspb.ResourceID{Id: vmId})
		require.NoError(t, err)
		require.NotNil(t, getPermitListAfterDeleteResp)
		assert.Equal(t, permitList.AssociatedResource, getPermitListAfterDeleteResp.AssociatedResource)
		assert.Empty(t, getPermitListAfterDeleteResp.Rules)
	}
}
