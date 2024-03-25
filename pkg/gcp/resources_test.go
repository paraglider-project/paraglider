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
	project := "project-1"
	zone := "us-central1-a"
	instanceName := "instance-1"
	instanceUri := fmt.Sprintf("projects/%s/zones/%s/instances/%s", project, zone, instanceName)

	resourceInfo, err := parseResourceUri(instanceUri)

	require.NoError(t, err)
	assert.Equal(t, project, resourceInfo.Project)
	assert.Equal(t, zone, resourceInfo.Zone)
	assert.Equal(t, instanceName, resourceInfo.Name)
	assert.Equal(t, instanceTypeName, resourceInfo.ResourceType)

	clusterName := "cluster-1"
	clusterUri := fmt.Sprintf("projects/%s/locations/%s/clusters/%s", project, zone, clusterName)

	resourceInfo, err = parseResourceUri(clusterUri)

	require.NoError(t, err)
	assert.Equal(t, project, resourceInfo.Project)
	assert.Equal(t, zone, resourceInfo.Zone)
	assert.Equal(t, clusterName, resourceInfo.Name)
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
	_, ctx, fakeClients := setup(t, &serverState)

	client := fakeClients.firewallsClient
	project := "project-1"
	resourceID := "resource-1"

	firewallRules, err := getFirewallRules(ctx, client, project, resourceID)

	require.NoError(t, err)
	assert.Equal(t, firewalls, firewallRules)
}

func TestGetResourceInfo(t *testing.T) {
	// Test for instance
	project := "project-1"
	zone := "us-central1-a"
	instanceName := "instance-1"
	resourceInfo := &ResourceInfo{Project: project, Zone: zone, Name: instanceName, ResourceType: instanceTypeName}

	instance := getFakeInstance(true)
	serverState := fakeServerState{instance: instance}
	_, ctx, fakeClients := setup(t, &serverState)

	client := fakeClients.instancesClient

	subnet, resourceId, err := GetResourceInfo(ctx, client, nil, resourceInfo)

	require.NoError(t, err)
	assert.Equal(t, instance.Id, resourceId)
	assert.Equal(t, instance.NetworkInterfaces[0].Subnetwork, subnet)

	// Test for cluster
	clusterName := "cluster-1"
	resourceInfo = &ResourceInfo{Project: project, Zone: zone, Name: clusterName, ResourceType: clusterTypeName}

	cluster := getFakeCluster(true)
	serverState = fakeServerState{cluster: cluster}
	_, ctx, fakeClients = setup(t, &serverState)

	clusterClient := fakeClients.clusterClient

	subnet, resourceId, err = GetResourceInfo(ctx, nil, clusterClient, resourceInfo)

	require.NoError(t, err)
	assert.Equal(t, cluster.Id, resourceId)
	assert.Equal(t, cluster.Subnetwork, subnet)
}

func TestIsValidResource(t *testing.T) {
	// Test for instance
	project := "project-1"
	zone := "us-central1-a"
	instanceRequest := &computepb.InsertInstanceRequest{
		Project:          project,
		Zone:             zone,
		InstanceResource: getFakeInstance(false),
	}
	jsonReq, err := json.Marshal(instanceRequest)
	require.NoError(t, err)

	resource := &invisinetspb.ResourceDescription{Description: jsonReq}

	resourceInfo, err := IsValidResource(context.Background(), resource)

	require.NoError(t, err)
	assert.Equal(t, project, resourceInfo.Project)
	assert.Equal(t, zone, resourceInfo.Zone)
	assert.Equal(t, instanceRequest.InstanceResource.Name, resourceInfo.Name)
	assert.Equal(t, instanceTypeName, resourceInfo.ResourceType)

	// Test for cluster
	clusterRequest := &containerpb.CreateClusterRequest{
		ProjectId: project,
		Zone:      zone,
		Cluster:   getFakeCluster(false),
	}
	jsonReq, err = json.Marshal(clusterRequest)
	require.NoError(t, err)

	resource = &invisinetspb.ResourceDescription{Description: jsonReq}

	resourceInfo, err = IsValidResource(context.Background(), resource)

	require.NoError(t, err)
	assert.Equal(t, project, resourceInfo.Project)
	assert.Equal(t, zone, resourceInfo.Zone)
	assert.Equal(t, clusterRequest.Cluster.Name, resourceInfo.Name)
}

func TestReadAndProvisionResource(t *testing.T) {
	// ReadAndProvisionResource(ctx context.Context, resource *invisinetspb.ResourceDescription, subnetName string, resourceInfo *ResourceInfo, instanceClient *compute.InstancesClient, clusterClient *container.ClusterManagerClient) (string, string, error)

	// Test for instance
	project := "project-1"
	zone := "us-central1-a"
	instanceRequest := &computepb.InsertInstanceRequest{
		Project:          project,
		Zone:             zone,
		InstanceResource: getFakeInstance(false),
	}
	jsonReq, err := json.Marshal(instanceRequest)
	require.NoError(t, err)

	resource := &invisinetspb.ResourceDescription{Description: jsonReq}

	resourceInfo := &ResourceInfo{Project: project, Zone: zone, Name: "instance-1", ResourceType: instanceTypeName}
	serverState := fakeServerState{}
	_, ctx, fakeClients := setup(t, &serverState)

	client := fakeClients.instancesClient

	uri, _, err := ReadAndProvisionResource(ctx, resource, "subnet-1", resourceInfo, client, nil)

	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("projects/%s/zones/%s/instances/%s", project, zone, instanceRequest.InstanceResource.Id), uri)
	// assert.Equal(t, ip, TODO now: fix this

	// Test for cluster
	clusterRequest := &containerpb.CreateClusterRequest{
		ProjectId: project,
		Zone:      zone,
		Cluster:   getFakeCluster(false),
	}
	jsonReq, err = json.Marshal(clusterRequest)
	require.NoError(t, err)

	resource = &invisinetspb.ResourceDescription{Description: jsonReq}

	resourceInfo = &ResourceInfo{Project: project, Zone: zone, Name: "cluster-1", ResourceType: clusterTypeName}

	clusterClient := fakeClients.clusterClient

	uri, _, err = ReadAndProvisionResource(ctx, resource, "subnet-1", resourceInfo, nil, clusterClient)

	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("projects/%s/zones/%s/instances/%s", project, zone, clusterRequest.Cluster.Name), uri)
	// assert.Equal(t, ip, TODO now: fix this
}

func TestInstanceGetNetworkInfo(t *testing.T) {
	// GetNetworkInfo(ctx context.Context, resourceInfo *ResourceInfo, client *compute.InstancesClient) (*ResourceNetworkInfo, error)
	instanceHandler := &GCPInstance{}
	resourceInfo := &ResourceInfo{Project: "project-1", Zone: "us-central1-a", Name: "instance-1", ResourceType: instanceTypeName}
	instance := getFakeInstance(true)
	serverState := fakeServerState{instance: instance}
	_, ctx, fakeClients := setup(t, &serverState)

	client := fakeClients.instancesClient

	networkInfo, err := instanceHandler.GetNetworkInfo(ctx, resourceInfo, client)

	require.NoError(t, err)
	assert.Equal(t, instance.Id, networkInfo.ResourceID)
	assert.Contains(t, instance.NetworkInterfaces[0].Network, networkInfo.NetworkName)
	assert.Equal(t, instance.NetworkInterfaces[0].Subnetwork, networkInfo.SubnetURI)
}

func TestInstanceFromResourceDecription(t *testing.T) {
	instanceRequest := &computepb.InsertInstanceRequest{
		Project:          "project-1",
		Zone:             "us-central1-a",
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
	project := "project-1"
	zone := "us-central1-a"
	subnet := "subnet-1"
	instanceRequest := &computepb.InsertInstanceRequest{
		Project:          project,
		Zone:             zone,
		InstanceResource: getFakeInstance(false),
	}
	resourceInfo := &ResourceInfo{Project: project, Zone: zone, Name: "instance-1", ResourceType: instanceTypeName}
	serverState := fakeServerState{}
	_, ctx, fakeClients := setup(t, &serverState)

	client := fakeClients.instancesClient

	uri, _, err := instanceHandler.CreateWithNetwork(ctx, instanceRequest, subnet, resourceInfo, client)

	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("projects/%s/zones/%s/instances/%s", project, zone, instanceRequest.InstanceResource.Id), uri)
	// assert.Equal(t, ip, TODO now: fix this

}

func TestGKEGetNetworkInfo(t *testing.T) {
	clusterHandler := &GKE{}
	resourceInfo := &ResourceInfo{Project: "project-1", Zone: "us-central1-a", Name: "cluster-1", ResourceType: clusterTypeName}
	cluster := getFakeCluster(true)
	serverState := fakeServerState{cluster: cluster}
	_, ctx, fakeClients := setup(t, &serverState)

	client := fakeClients.clusterClient

	networkInfo, err := clusterHandler.GetNetworkInfo(ctx, resourceInfo, client)

	require.NoError(t, err)
	assert.Equal(t, cluster.Id, networkInfo.ResourceID)
	assert.Equal(t, cluster.Subnetwork, networkInfo.SubnetURI)
}

func TestGKEFromResourceDecription(t *testing.T) {
	clusterRequest := &containerpb.CreateClusterRequest{
		ProjectId: "project-1",
		Zone:      "us-central1-a",
		Cluster:   getFakeCluster(false),
	}
	json, err := json.Marshal(clusterRequest)
	require.NoError(t, err)

	clusterHandler := &GKE{}
	clusterParsed, err := clusterHandler.FromResourceDecription(json)

	require.NoError(t, err)
	assert.Equal(t, clusterRequest.ProjectId, clusterParsed.ProjectId)
	assert.Equal(t, clusterRequest.Cluster.Id, clusterParsed.Cluster.Id)
}

func TestGKECreateWithNetwork(t *testing.T) {
	clusterHandler := &GKE{}
	project := "project-1"
	zone := "us-central1-a"
	subnet := "subnet-1"
	clusterRequest := &containerpb.CreateClusterRequest{
		ProjectId: project,
		Zone:      zone,
		Cluster:   getFakeCluster(false),
	}
	resourceInfo := &ResourceInfo{Project: project, Zone: zone, Name: "instance-1", ResourceType: instanceTypeName}
	serverState := fakeServerState{}
	_, ctx, fakeClients := setup(t, &serverState)

	client := fakeClients.clusterClient

	uri, _, err := clusterHandler.CreateWithNetwork(ctx, clusterRequest, subnet, resourceInfo, client)

	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("projects/%s/zones/%s/instances/%s", project, zone, clusterRequest.Cluster.Name), uri)
	// assert.Equal(t, ip, TODO now: fix this
}
