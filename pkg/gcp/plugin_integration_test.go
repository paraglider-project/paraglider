//go:build integration

/*
Copyright 2023 The Paraglider Authors.

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
	"strconv"
	"strings"
	"testing"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	fake "github.com/paraglider-project/paraglider/pkg/fake/orchestrator/rpc"
	"github.com/paraglider-project/paraglider/pkg/orchestrator"
	"github.com/paraglider-project/paraglider/pkg/orchestrator/config"
	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createInstance(ctx context.Context, server *GCPPluginServer, project string, namespace string, zone string, name string) (*paragliderpb.CreateResourceResponse, error) {
	insertInstanceReq := GetTestVmParameters(project, zone, name)
	insertInstanceReqBytes, err := json.Marshal(insertInstanceReq)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal insert instance request: %w", err)
	}
	resourceDescription := &paragliderpb.CreateResourceRequest{
		Deployment:  &paragliderpb.ParagliderDeployment{Id: "projects/" + project, Namespace: namespace},
		Name:        name,
		Description: insertInstanceReqBytes,
	}
	return server.CreateResource(ctx, resourceDescription)
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
	namespace := "default"
	s := &GCPPluginServer{orchestratorServerAddr: fakeOrchestratorServerAddr}
	ctx := context.Background()

	// Create VM in a clean state (i.e. no VPC or subnet)
	vm1Name := "vm-paraglider-test-1"
	vm1Zone := "us-west1-a"
	insertInstanceReq1 := GetTestVmParameters(projectId, vm1Zone, vm1Name)
	insertInstanceReq1Bytes, err := json.Marshal(insertInstanceReq1)
	if err != nil {
		t.Fatal(err)
	}
	resourceDescription1 := &paragliderpb.CreateResourceRequest{
		Deployment:  &paragliderpb.ParagliderDeployment{Id: "projects/" + projectId, Namespace: namespace},
		Name:        vm1Name,
		Description: insertInstanceReq1Bytes,
	}
	createResource1Resp, err := s.CreateResource(
		ctx,
		resourceDescription1,
	)
	require.NoError(t, err)
	require.NotNil(t, createResource1Resp)
	assert.Equal(t, createResource1Resp.Name, vm1Name)

	// Create VM in different region (i.e. requires new subnet to be created)
	vm2Name := "vm-paraglider-test-2"
	vm2Zone := "us-east1-b"
	insertInstanceReq2 := GetTestVmParameters(projectId, vm2Zone, vm2Name)
	insertInstanceReq2Bytes, err := json.Marshal(insertInstanceReq2)
	if err != nil {
		t.Fatal(err)
	}
	resourceDescription2 := &paragliderpb.CreateResourceRequest{
		Deployment:  &paragliderpb.ParagliderDeployment{Id: "projects/" + projectId, Namespace: namespace},
		Name:        vm2Name,
		Description: insertInstanceReq2Bytes,
	}
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
	vm1Url := getInstanceUrl(projectId, vm1Zone, vm1Name)
	vm2Url := getInstanceUrl(projectId, vm2Zone, vm2Name)
	vm1Ip, err := GetInstanceIpAddress(projectId, vm1Zone, vm1Name)
	require.NoError(t, err)
	vm2Ip, err := GetInstanceIpAddress(projectId, vm2Zone, vm2Name)
	require.NoError(t, err)

	vmUrls := []string{vm1Url, vm2Url}
	rules1 := []*paragliderpb.PermitListRule{
		{
			Name:      "test-rule1",
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{vm2Ip},
		},
		{
			Name:      "test-rule2",
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{vm2Ip},
		},
	}
	rules2 := []*paragliderpb.PermitListRule{
		{
			Name:      "test-rule3",
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{vm1Ip},
		},
		{
			Name:      "test-rule4",
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{vm1Ip},
		},
	}
	ruleLists := [][]*paragliderpb.PermitListRule{rules1, rules2}
	for i, vmUrl := range vmUrls {
		rules := ruleLists[i]
		addPermitListRulesResp, err := s.AddPermitListRules(ctx, &paragliderpb.AddPermitListRulesRequest{Rules: rules, Namespace: namespace, Resource: vmUrl})
		require.NoError(t, err)
		require.NotNil(t, addPermitListRulesResp)

		getPermitListAfterAddResp, err := s.GetPermitList(ctx, &paragliderpb.GetPermitListRequest{Resource: vmUrl, Namespace: namespace})
		require.NoError(t, err)
		require.NotNil(t, getPermitListAfterAddResp)

		// TODO @seankimkdy: use this in all of the codebase to ensure permitlists are being compared properly
		assert.ElementsMatch(t, rules, getPermitListAfterAddResp.Rules)
	}

	// Run connectivity tests on both directions between vm1 and vm2
	vm1ToVm2TestResult, err := RunIcmpConnectivityTest("vm1-to-vm2", projectId, namespace, vm1Name, vm1Zone, vm2Ip, 5)
	require.NoError(t, err)
	require.True(t, vm1ToVm2TestResult)
	vm2toVm1TestResult, err := RunIcmpConnectivityTest("vm2-to-vm1", projectId, namespace, vm2Name, vm2Zone, vm1Ip, 5)
	require.NoError(t, err)
	require.True(t, vm2toVm1TestResult)

	// Delete permit lists
	for i, vmId := range vmUrls {
		ruleNames := []string{ruleLists[i][0].Name, ruleLists[i][1].Name}
		deletePermitListRulesResp, err := s.DeletePermitListRules(ctx, &paragliderpb.DeletePermitListRulesRequest{RuleNames: ruleNames, Namespace: "default", Resource: vmId})
		require.NoError(t, err)
		require.NotNil(t, deletePermitListRulesResp)

		getPermitListAfterDeleteResp, err := s.GetPermitList(ctx, &paragliderpb.GetPermitListRequest{Resource: vmId, Namespace: namespace})
		require.NoError(t, err)
		require.NotNil(t, getPermitListAfterDeleteResp)
		assert.Empty(t, getPermitListAfterDeleteResp.Rules)
	}
}

func TestCrossNamespace(t *testing.T) {
	// Create two projects
	project1Id := SetupGcpTesting("integration1")
	defer TeardownGcpTesting(project1Id)
	project2Id := SetupGcpTesting("integration2")
	defer TeardownGcpTesting(project2Id)

	// Set GCP plugin port
	gcpServerPort := 7992

	// Setup orchestrator server
	project1Namespace := "project1"
	project2Namespace := "project2"
	orchestratorServerConfig := config.Config{
		Server: config.Server{
			Host:    "localhost",
			Port:    "8082",
			RpcPort: "8083",
		},
		CloudPlugins: []config.CloudPlugin{
			{
				Name: utils.GCP,
				Host: "localhost",
				Port: strconv.Itoa(gcpServerPort),
			},
		},
		Namespaces: map[string][]config.CloudDeployment{
			project1Namespace: {
				{
					Name:       utils.GCP,
					Deployment: fmt.Sprintf("projects/%s", project1Id),
				},
			},
			project2Namespace: {
				{
					Name:       utils.GCP,
					Deployment: fmt.Sprintf("projects/%s", project2Id),
				},
			},
		},
	}
	orchestratorServerAddr := orchestratorServerConfig.Server.Host + ":" + orchestratorServerConfig.Server.RpcPort
	orchestrator.Setup(orchestratorServerConfig, true)

	// Setup GCP plugin server
	gcpServer := Setup(gcpServerPort, orchestratorServerAddr)
	ctx := context.Background()

	// Create vm1 in project1
	vm1Name := "vm-paraglider-test1"
	vm1Zone := "us-west1-a"
	createVm1Resp, err := createInstance(ctx, gcpServer, project1Id, project1Namespace, vm1Zone, vm1Name)
	require.NoError(t, err)
	require.NotNil(t, createVm1Resp)
	assert.Equal(t, createVm1Resp.Name, vm1Name)

	// Create vm2 in project2
	vm2Name := "vm-paraglider-test-2"
	vm2Zone := "us-west1-a"
	createVm2Resp, err := createInstance(ctx, gcpServer, project2Id, project2Namespace, vm2Zone, vm2Name)
	require.NoError(t, err)
	require.NotNil(t, createVm2Resp)
	assert.Equal(t, createVm2Resp.Name, vm2Name)

	// Add permit list rules to vm1 and vm2 to ping each other
	vm1Url := getInstanceUrl(project1Id, vm1Zone, vm1Name)
	vm2Url := getInstanceUrl(project2Id, vm2Zone, vm2Name)
	vm1Ip, err := GetInstanceIpAddress(project1Id, vm1Zone, vm1Name)
	require.NoError(t, err)
	vm2Ip, err := GetInstanceIpAddress(project2Id, vm2Zone, vm2Name)
	require.NoError(t, err)
	vmUrls := []string{vm1Url, vm2Url}
	vm1Rules := []*paragliderpb.PermitListRule{
		{
			Name:      "vm2-ping-ingress",
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{vm2Ip},
		},
		{
			Name:      "vm2-ping-egress",
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{vm2Ip},
		},
	}
	vm2Rules := []*paragliderpb.PermitListRule{
		{
			Name:      "vm1-ping-ingress",
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{vm1Ip},
		},
		{
			Name:      "vm1-ping-egress",
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{vm1Ip},
		},
	}
	vmRules := [][]*paragliderpb.PermitListRule{vm1Rules, vm2Rules}
	namespaces := []string{project1Namespace, project2Namespace}
	for i, vmUrl := range vmUrls {
		addPermitListRulesReq := &paragliderpb.AddPermitListRulesRequest{Rules: vmRules[i], Namespace: namespaces[i], Resource: vmUrl}
		addPermitListRulesResp, err := gcpServer.AddPermitListRules(ctx, addPermitListRulesReq)
		require.NoError(t, err)
		require.NotNil(t, addPermitListRulesResp)
	}

	// Run connectivity tests on both directions between vm1 and vm2
	vm1ToVm2TestResult, err := RunIcmpConnectivityTest("vm1-to-vm2", project1Id, project1Namespace, vm1Name, vm1Zone, vm2Ip, 5)
	require.NoError(t, err)
	require.True(t, vm1ToVm2TestResult)
	vm2toVm1TestResult, err := RunIcmpConnectivityTest("vm2-to-vm1", project2Id, project2Namespace, vm2Name, vm2Zone, vm1Ip, 5)
	require.NoError(t, err)
	require.True(t, vm2toVm1TestResult)
}

func TestPublicIpAddressTarget(t *testing.T) {
	// Setup
	projectId := SetupGcpTesting("integration-public-ip")
	defer TeardownGcpTesting(projectId)
	_, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.GCP)
	if err != nil {
		t.Fatal(err)
	}
	namespace := "default"
	s := &GCPPluginServer{orchestratorServerAddr: fakeOrchestratorServerAddr}
	ctx := context.Background()

	// Create VM
	vmName := "vm-paraglider-test-1"
	vmZone := "us-west1-a"
	insertInstanceReq := GetTestVmParameters(projectId, vmZone, vmName)
	insertInstanceReqBytes, err := json.Marshal(insertInstanceReq)
	if err != nil {
		t.Fatal(err)
	}
	createResourceReq := &paragliderpb.CreateResourceRequest{
		Deployment:  &paragliderpb.ParagliderDeployment{Id: "projects/" + projectId, Namespace: namespace},
		Name:        vmName,
		Description: insertInstanceReqBytes,
	}
	createResourceResp, err := s.CreateResource(ctx, createResourceReq)
	require.NoError(t, err)
	require.NotNil(t, createResourceResp)
	assert.Equal(t, createResourceResp.Name, vmName)

	// Create permit list rules to Cloudflare DNS
	// Multiple permit list rules are tested to ensure that duplicate NAT gateway creations are avoided
	permitListRules := []*paragliderpb.PermitListRule{
		{
			Name:      "cloudflare-dns-tcp-outbound",
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   80,
			Protocol:  6,
			Targets:   []string{"1.1.1.1"},
		},
		{
			Name:      "cloudflare-dns-icmp-outbound",
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{"1.1.1.1"},
		},
	}
	vmUrl := getInstanceUrl(projectId, vmZone, vmName)
	addPermitListReq := &paragliderpb.AddPermitListRulesRequest{Rules: permitListRules, Namespace: namespace, Resource: vmUrl}
	addPermitListResp, err := s.AddPermitListRules(ctx, addPermitListReq)
	require.NoError(t, err)
	require.NotNil(t, addPermitListResp)

	// Run connectivity tests
	cloudflareDnsTcpTestResult, err := RunTcpConnectivityTest("cloudflare-dns-tcp", projectId, namespace, vmName, vmZone, "1.1.1.1", 80, 5)
	require.NoError(t, err)
	require.True(t, cloudflareDnsTcpTestResult)
	cloudflareDnsIcmpTestResult, err := RunIcmpConnectivityTest("cloudflare-dns-icmp", projectId, namespace, vmName, vmZone, "1.1.1.1", 5)
	require.NoError(t, err)
	require.True(t, cloudflareDnsIcmpTestResult)
}
