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
	fake "github.com/NetSys/invisinets/pkg/fake/controller/rpc"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	utils "github.com/NetSys/invisinets/pkg/utils"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

const namespace = "default"

func checkPermitListsEqual(instanceId uint64, pl1 *invisinetspb.PermitList, pl2 *invisinetspb.PermitList) bool {
	sortPermitListRuleOpt := protocmp.SortRepeated(func(plr1, plr2 *invisinetspb.PermitListRule) bool {
		return getFirewallName(plr1, instanceId) < getFirewallName(plr2, instanceId)
	})
	return cmp.Diff(pl1, pl2, protocmp.Transform(), sortPermitListRuleOpt) == ""
}

// Tests creating two vms in separate regions and basic add/delete/get permit list functionality
func TestIntegration(t *testing.T) {
	// Setup
	projectId := SetupGcpTesting("integration")
	defer TeardownGcpTesting(projectId)
	_, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.GCP)
	if err != nil {
		t.Fatal(err)
	}
	s := &GCPPluginServer{orchestratorServerAddr: fakeOrchestratorServerAddr}
	ctx := context.Background()

	// Create VM in a clean state (i.e. no VPC or subnet)
	vm1Name := "vm-invisinets-test-1"
	vm1Zone := "us-west1-a"
	insertInstanceReq1 := GetTestVmParameters(projectId, vm1Zone, vm1Name)
	insertInstanceReq1Bytes, err := json.Marshal(insertInstanceReq1)
	if err != nil {
		t.Fatal(err)
	}
	resourceDescription1 := &invisinetspb.ResourceDescription{Description: insertInstanceReq1Bytes, Namespace: namespace}
	createResource1Resp, err := s.CreateResource(
		ctx,
		resourceDescription1,
	)
	require.NoError(t, err)
	require.NotNil(t, createResource1Resp)
	assert.Equal(t, createResource1Resp.Name, vm1Name)

	// Create VM in different region (i.e. requires new subnet to be created)
	vm2Name := "vm-invisinets-test-2"
	vm2Zone := "us-east1-b"
	insertInstanceReq2 := GetTestVmParameters(projectId, vm2Zone, vm2Name)
	insertInstanceReq2Bytes, err := json.Marshal(insertInstanceReq2)
	if err != nil {
		t.Fatal(err)
	}
	resourceDescription2 := &invisinetspb.ResourceDescription{Description: insertInstanceReq2Bytes, Namespace: namespace}
	createResource2Resp, err := s.CreateResource(
		ctx,
		resourceDescription2,
	)
	require.NoError(t, err)
	require.NotNil(t, createResource2Resp)
	assert.Equal(t, createResource2Resp.Name, vm2Name)

	// Check VPC and subnetworks
	networksClient, err := compute.NewNetworksRESTClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	getNetworkReq := &computepb.GetNetworkRequest{
		Network: getVpcName(namespace),
		Project: projectId,
	}
	getNetworkResp, err := networksClient.Get(ctx, getNetworkReq)
	require.NoError(t, err)
	require.NotNil(t, getNetworkResp)
	subnetworks := make([]string, len(getNetworkResp.Subnetworks))
	for i, subnetURL := range getNetworkResp.Subnetworks {
		subnetworks[i] = subnetURL[strings.LastIndex(subnetURL, "/")+1:]
	}
	assert.ElementsMatch(
		t,
		[]string{getSubnetworkName(namespace, "us-west1"), getSubnetworkName(namespace, "us-east1")},
		subnetworks,
	)

	// Check default deny all egress rule exists
	firewallsClient, err := compute.NewFirewallsRESTClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	getFirewallReq := &computepb.GetFirewallRequest{
		Project:  projectId,
		Firewall: getDenyAllIngressFirewallName(namespace),
	}
	getFirewallResp, err := firewallsClient.Get(ctx, getFirewallReq)
	require.NoError(t, err)
	require.NotNil(t, getFirewallResp)

	// Add bidirectional PING permit list rules
	vm1Uri := fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectId, vm1Zone, vm1Name)
	vm2Uri := fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectId, vm2Zone, vm2Name)
	vm1Ip, err := GetInstanceIpAddress(projectId, vm1Zone, vm1Name)
	require.NoError(t, err)
	vm2Ip, err := GetInstanceIpAddress(projectId, vm2Zone, vm2Name)
	require.NoError(t, err)

	vmUris := []string{vm1Uri, vm2Uri}
	permitLists := [2]*invisinetspb.PermitList{
		{
			AssociatedResource: vm1Uri,
			Rules: []*invisinetspb.PermitListRule{
				{
					Direction: invisinetspb.Direction_INBOUND,
					SrcPort:   -1,
					DstPort:   -1,
					Protocol:  1,
					Targets:   []string{vm2Ip},
				},
				{
					Direction: invisinetspb.Direction_OUTBOUND,
					SrcPort:   -1,
					DstPort:   -1,
					Protocol:  1,
					Targets:   []string{vm2Ip},
				},
			},
			Namespace: namespace,
		},
		{
			AssociatedResource: vm2Uri,
			Rules: []*invisinetspb.PermitListRule{
				{
					Direction: invisinetspb.Direction_INBOUND,
					SrcPort:   -1,
					DstPort:   -1,
					Protocol:  1,
					Targets:   []string{vm1Ip},
				},
				{
					Direction: invisinetspb.Direction_OUTBOUND,
					SrcPort:   -1,
					DstPort:   -1,
					Protocol:  1,
					Targets:   []string{vm1Ip},
				},
			},
			Namespace: namespace,
		},
	}
	vm1Id, err := GetInstanceId(projectId, vm1Zone, vm1Name)
	if err != nil {
		t.Fatal(err)
	}
	vm2Id, err := GetInstanceId(projectId, vm2Zone, vm2Name)
	if err != nil {
		t.Fatal(err)
	}
	vmIds := []uint64{vm1Id, vm2Id}
	for i, vmUri := range vmUris {
		permitList := permitLists[i]
		addPermitListRulesResp, err := s.AddPermitListRules(ctx, permitList)
		require.NoError(t, err)
		require.NotNil(t, addPermitListRulesResp)
		assert.True(t, addPermitListRulesResp.Success)

		getPermitListAfterAddResp, err := s.GetPermitList(ctx, &invisinetspb.ResourceID{Id: vmUri, Namespace: namespace})
		require.NoError(t, err)
		require.NotNil(t, getPermitListAfterAddResp)

		// TODO @seankimkdy: use this in all of the codebase to ensure permitlists are being compared properly
		assert.True(t, checkPermitListsEqual(vmIds[i], permitList, getPermitListAfterAddResp))
	}

	// Connectivity tests that ping the two VMs
	vm1Endpoint := &networkmanagementpb.Endpoint{
		IpAddress: vm1Ip,
		Network:   "projects/" + projectId + "/" + GetVpcUri(namespace),
		ProjectId: projectId,
	}
	vm2Endpoint := &networkmanagementpb.Endpoint{
		IpAddress: vm2Ip,
		Network:   "projects/" + projectId + "/" + GetVpcUri(namespace),
		ProjectId: projectId,
	}

	// Run connectivity tests on both directions between vm1 and vm2
	RunPingConnectivityTest(t, projectId, "1to2", vm1Endpoint, vm2Endpoint)
	RunPingConnectivityTest(t, projectId, "2to1", vm2Endpoint, vm1Endpoint)

	// Delete permit lists
	for i, vmId := range vmUris {
		permitList := permitLists[i]
		deletePermitListRulesResp, err := s.DeletePermitListRules(ctx, permitList)
		require.NoError(t, err)
		require.NotNil(t, deletePermitListRulesResp)
		assert.True(t, deletePermitListRulesResp.Success)

		getPermitListAfterDeleteResp, err := s.GetPermitList(ctx, &invisinetspb.ResourceID{Id: vmId, Namespace: namespace})
		require.NoError(t, err)
		require.NotNil(t, getPermitListAfterDeleteResp)
		assert.Equal(t, permitList.AssociatedResource, getPermitListAfterDeleteResp.AssociatedResource)
		assert.Empty(t, getPermitListAfterDeleteResp.Rules)
	}
}
