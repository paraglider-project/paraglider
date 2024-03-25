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
	"testing"

	computepb "cloud.google.com/go/compute/apiv1/computepb"
	containerpb "cloud.google.com/go/container/apiv1/containerpb"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseResourceURI(t *testing.T) {
	instanceUri := fmt.Sprintf("projects/%s/zones/%s/instances/%s", fakeProject, fakeZone, fakeInstanceName)

	resourceInfo, err := parseResourceUri(instanceUri)

	require.NoError(t, err)
	assert.Equal(t, fakeProject, resourceInfo.Project)
	assert.Equal(t, fakeZone, resourceInfo.Zone)
	assert.Equal(t, fakeInstanceName, resourceInfo.Name)
	assert.Equal(t, instanceTypeName, resourceInfo.ResourceType)

	clusterUri := fmt.Sprintf("projects/%s/zones/%s/clusters/%s", fakeProject, fakeZone, fakeClusterName)

	resourceInfo, err = parseResourceUri(clusterUri)

	require.NoError(t, err)
	assert.Equal(t, fakeProject, resourceInfo.Project)
	assert.Equal(t, fakeZone, resourceInfo.Zone)
	assert.Equal(t, fakeClusterName, resourceInfo.Name)
	assert.Equal(t, clusterTypeName, resourceInfo.ResourceType)
}

func TestGetFirewallRules(t *testing.T) {
	// etFirewallRules(ctx context.Context, client *compute.FirewallsClient, project string, resourceID string) ([]*computepb.Firewall, error)
	firewalls := []*computepb.Firewall{{Name: to.Ptr("firewall-1")}, {Name: to.Ptr("firewall-2")}} // TODO now: fix naming and find out if this is a get request or not
	fwMap := make(map[string]*computepb.Firewall)
	for _, fw := range firewalls {
		fwMap[*fw.Name] = fw
	}
	serverState := fakeServerState{firewallMap: fwMap}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	client := fakeClients.firewallsClient
	project := fakeProject
	resourceID := "resource-1"

	firewallRules, err := getFirewallRules(ctx, client, project, resourceID)

	expectedFwNames := []string{"firewall-1", "firewall-2"}

	require.NoError(t, err)
	assert.Contains(t, expectedFwNames, *firewallRules[0].Name)
	assert.Contains(t, expectedFwNames, *firewallRules[1].Name)
}

func TestGetResourceInfo(t *testing.T) {
	// Test for instance
	resourceInfo := &ResourceInfo{Project: fakeProject, Zone: fakeZone, Name: fakeInstanceName, ResourceType: instanceTypeName, Namespace: fakeNamespace}

	instance := getFakeInstance(true)
	serverState := fakeServerState{instance: instance}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	client := fakeClients.instancesClient

	subnet, resourceId, err := GetResourceInfo(ctx, client, nil, resourceInfo)

	require.NoError(t, err)
	assert.Equal(t, convertInstanceIdToString(*instance.Id), *resourceId)
	assert.Equal(t, instance.NetworkInterfaces[0].Subnetwork, subnet)

	// Test for cluster
	resourceInfo = &ResourceInfo{Project: fakeProject, Zone: fakeZone, Name: fakeClusterName, ResourceType: clusterTypeName, Namespace: fakeNamespace}

	cluster := getFakeCluster(true)
	serverState = fakeServerState{cluster: cluster}
	fakeServer, ctx, fakeClients, fakeGRPCServer = setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	clusterClient := fakeClients.clusterClient

	subnet, resourceId, err = GetResourceInfo(ctx, nil, clusterClient, resourceInfo)

	require.NoError(t, err)
	assert.Equal(t, cluster.Id, *resourceId)
	assert.Equal(t, cluster.Subnetwork, *subnet)
}

func TestIsValidResource(t *testing.T) {
	// Test for instance
	instanceRequest := &computepb.InsertInstanceRequest{
		Project:          fakeProject,
		Zone:             fakeZone,
		InstanceResource: getFakeInstance(false),
	}
	jsonReq, err := json.Marshal(instanceRequest)
	require.NoError(t, err)

	resource := &invisinetspb.ResourceDescription{Description: jsonReq}

	resourceInfo, err := IsValidResource(context.Background(), resource)

	require.NoError(t, err)
	assert.Equal(t, fakeProject, resourceInfo.Project)
	assert.Equal(t, fakeZone, resourceInfo.Zone)

	// Test for cluster
	clusterRequest := &containerpb.CreateClusterRequest{
		Parent:  fmt.Sprintf("projects/%s/locations/%s", fakeProject, fakeZone),
		Cluster: getFakeCluster(false),
	}
	jsonReq, err = json.Marshal(clusterRequest)
	require.NoError(t, err)

	resource = &invisinetspb.ResourceDescription{Description: jsonReq}

	resourceInfo, err = IsValidResource(context.Background(), resource)

	require.NoError(t, err)
	assert.Equal(t, fakeProject, resourceInfo.Project)
	assert.Equal(t, fakeZone, resourceInfo.Zone)
	assert.Equal(t, clusterRequest.Cluster.Name, resourceInfo.Name)
}

func TestReadAndProvisionResource(t *testing.T) {
	// ReadAndProvisionResource(ctx context.Context, resource *invisinetspb.ResourceDescription, subnetName string, resourceInfo *ResourceInfo, instanceClient *compute.InstancesClient, clusterClient *container.ClusterManagerClient) (string, string, error)

	// Test for instance
	instanceRequest := &computepb.InsertInstanceRequest{
		Project:          fakeProject,
		Zone:             fakeZone,
		InstanceResource: getFakeInstance(false),
	}
	jsonReq, err := json.Marshal(instanceRequest)
	require.NoError(t, err)

	resource := &invisinetspb.ResourceDescription{Description: jsonReq}

	resourceInfo := &ResourceInfo{Project: fakeProject, Zone: fakeZone, Name: fakeInstanceName, ResourceType: instanceTypeName}
	serverState := fakeServerState{instance: getFakeInstance(true)}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	client := fakeClients.instancesClient

	uri, _, err := ReadAndProvisionResource(ctx, resource, "subnet-1", resourceInfo, client, nil)

	require.NoError(t, err)
	assert.Contains(t, uri, *instanceRequest.InstanceResource.Name)
	// assert.Equal(t, ip, TODO now: fix this

	// Test for cluster
	clusterRequest := &containerpb.CreateClusterRequest{
		ProjectId: fakeProject,
		Zone:      fakeZone,
		Cluster:   getFakeCluster(false),
	}
	jsonReq, err = json.Marshal(clusterRequest)
	require.NoError(t, err)

	resource = &invisinetspb.ResourceDescription{Description: jsonReq}

	resourceInfo = &ResourceInfo{Project: fakeProject, Zone: fakeZone, Name: fakeClusterName, ResourceType: clusterTypeName}

	clusterClient := fakeClients.clusterClient

	fmt.Printf("Clusteroptions: %v\n", clusterClient.CallOptions.GetCluster)

	uri, _, err = ReadAndProvisionResource(ctx, resource, "subnet-1", resourceInfo, nil, clusterClient)

	require.NoError(t, err)
	assert.Equal(t, getClusterUri(fakeProject, fakeZone, clusterRequest.Cluster.Name), uri)
	// assert.Equal(t, ip, TODO now: fix this
}

func TestInstanceGetNetworkInfo(t *testing.T) {
	// GetNetworkInfo(ctx context.Context, resourceInfo *ResourceInfo, client *compute.InstancesClient) (*ResourceNetworkInfo, error)
	instanceHandler := &GCPInstance{}
	resourceInfo := &ResourceInfo{Project: fakeProject, Zone: fakeZone, Name: fakeInstanceName, ResourceType: instanceTypeName}
	instance := getFakeInstance(true)
	serverState := fakeServerState{instance: instance}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	client := fakeClients.instancesClient

	networkInfo, err := instanceHandler.GetNetworkInfo(ctx, resourceInfo, client)

	require.NoError(t, err)
	assert.Equal(t, convertInstanceIdToString(*instance.Id), networkInfo.ResourceID)
	assert.Contains(t, *instance.NetworkInterfaces[0].Network, networkInfo.NetworkName)
	assert.Equal(t, *instance.NetworkInterfaces[0].Subnetwork, networkInfo.SubnetURI)
}

func TestInstanceFromResourceDecription(t *testing.T) {
	instanceRequest := &computepb.InsertInstanceRequest{
		Project:          fakeProject,
		Zone:             fakeZone,
		InstanceResource: getFakeInstance(false),
	}
	json, err := json.Marshal(instanceRequest)
	require.NoError(t, err)

	instanceHandler := &GCPInstance{}
	instanceParsed, err := instanceHandler.FromResourceDecription(json)

	require.NoError(t, err)
	assert.Equal(t, instanceRequest.Project, instanceParsed.Project)
	assert.Equal(t, instanceRequest.InstanceResource.Id, instanceParsed.InstanceResource.Id)
}

func TestInstanceCreateWithNetwork(t *testing.T) {
	// CreateWithNetwork(ctx context.Context, instance *computepb.InsertInstanceRequest, subnetName string, resourceInfo *ResourceInfo, client *compute.InstancesClient) (string, string, error)
	instanceHandler := &GCPInstance{}
	subnet := "subnet-1"
	instanceRequest := &computepb.InsertInstanceRequest{
		Project:          fakeProject,
		Zone:             fakeZone,
		InstanceResource: getFakeInstance(false),
	}
	resourceInfo := &ResourceInfo{Project: fakeProject, Zone: fakeZone, Name: fakeInstanceName, ResourceType: instanceTypeName}
	serverState := fakeServerState{instance: getFakeInstance(true)}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	client := fakeClients.instancesClient

	uri, _, err := instanceHandler.CreateWithNetwork(ctx, instanceRequest, subnet, resourceInfo, client)

	require.NoError(t, err)
	assert.Contains(t, uri, *instanceRequest.InstanceResource.Name)
	// assert.Equal(t, ip, TODO now: fix this

}

func TestGKEGetNetworkInfo(t *testing.T) {
	clusterHandler := &GKE{}
	resourceInfo := &ResourceInfo{Project: fakeProject, Zone: fakeZone, Name: fakeClusterName, ResourceType: clusterTypeName}
	cluster := getFakeCluster(true)
	serverState := fakeServerState{cluster: cluster}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	client := fakeClients.clusterClient

	networkInfo, err := clusterHandler.GetNetworkInfo(ctx, resourceInfo, client)

	require.NoError(t, err)
	assert.Equal(t, cluster.Id, networkInfo.ResourceID)
	assert.Equal(t, cluster.Subnetwork, networkInfo.SubnetURI)
}

func TestGKEFromResourceDecription(t *testing.T) {
	clusterRequest := &containerpb.CreateClusterRequest{
		Cluster: getFakeCluster(false),
	}
	json, err := json.Marshal(clusterRequest)
	require.NoError(t, err)

	clusterHandler := &GKE{}
	clusterParsed, err := clusterHandler.FromResourceDecription(json)

	require.NoError(t, err)
	assert.Equal(t, clusterRequest.Cluster.Id, clusterParsed.Cluster.Id)
}

func TestGKECreateWithNetwork(t *testing.T) {
	clusterHandler := &GKE{}
	subnet := "subnet-1"
	clusterRequest := &containerpb.CreateClusterRequest{
		Cluster: getFakeCluster(false),
		Parent:  "projects/project-1/locations/zone-1",
	}
	resourceInfo := &ResourceInfo{Project: fakeProject, Zone: fakeZone, Name: fakeInstanceName, ResourceType: instanceTypeName}
	serverState := fakeServerState{}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	client := fakeClients.clusterClient

	uri, _, err := clusterHandler.CreateWithNetwork(ctx, clusterRequest, subnet, resourceInfo, client)

	require.NoError(t, err)
	assert.Equal(t, getClusterUri(fakeProject, fakeZone, clusterRequest.Cluster.Name), uri)
	// assert.Equal(t, ip, TODO now: fix this
}
