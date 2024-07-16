//go:build unit

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
	"testing"

	computepb "cloud.google.com/go/compute/apiv1/computepb"
	containerpb "cloud.google.com/go/container/apiv1/containerpb"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func getFakeInstanceResourceDescription() (*paragliderpb.CreateResourceRequest, *computepb.InsertInstanceRequest, error) {
	instanceRequest := &computepb.InsertInstanceRequest{
		Zone:             fakeZone,
		InstanceResource: getFakeInstance(false),
	}
	jsonReq, err := json.Marshal(instanceRequest)
	if err != nil {
		return nil, nil, err
	}

	resource := &paragliderpb.CreateResourceRequest{Name: fakeInstanceName, Description: jsonReq}
	return resource, instanceRequest, nil
}

func getFakeClusterResourceDescription() (*paragliderpb.CreateResourceRequest, *containerpb.CreateClusterRequest, error) {
	clusterRequest := &containerpb.CreateClusterRequest{
		Zone:    fakeZone,
		Parent:  fmt.Sprintf("projects/%s/locations/%s", fakeProject, fakeZone),
		Cluster: getFakeCluster(false),
	}
	jsonReq, err := json.Marshal(clusterRequest)
	if err != nil {
		return nil, nil, err
	}

	resource := &paragliderpb.CreateResourceRequest{Name: fakeClusterName, Description: jsonReq}
	return resource, clusterRequest, nil
}

func getFakeServiceAttachment() *computepb.ServiceAttachment {
	return &computepb.ServiceAttachment{
		Id:       proto.Uint64(fakeServiceAttachmentId),
		SelfLink: proto.String(fakeServiceAttachmentUrl),
	}
}

func getFakePSCRequest() (*paragliderpb.CreateResourceRequest, *ServiceAttachmentDescription, error) {
	description := &ServiceAttachmentDescription{Url: fakeServiceAttachmentUrl}
	jsonReq, err := json.Marshal(description)
	if err != nil {
		return nil, nil, err
	}

	resource := &paragliderpb.CreateResourceRequest{Description: jsonReq}
	return resource, description, nil
}

func TestParseResourceUrl(t *testing.T) {
	instanceUrl := fmt.Sprintf("projects/%s/zones/%s/instances/%s", fakeProject, fakeZone, fakeInstanceName)

	resourceInfo, err := parseResourceUrl(instanceUrl)

	require.NoError(t, err)
	assert.Equal(t, fakeProject, resourceInfo.Project)
	assert.Equal(t, fakeZone, resourceInfo.Zone)
	assert.Equal(t, fakeInstanceName, resourceInfo.Name)
	assert.Equal(t, instanceTypeName, resourceInfo.ResourceType)

	clusterUrl := fmt.Sprintf("projects/%s/locations/%s/clusters/%s", fakeProject, fakeZone, fakeClusterName)

	resourceInfo, err = parseResourceUrl(clusterUrl)

	require.NoError(t, err)
	assert.Equal(t, fakeProject, resourceInfo.Project)
	assert.Equal(t, fakeZone, resourceInfo.Zone)
	assert.Equal(t, fakeClusterName, resourceInfo.Name)
	assert.Equal(t, clusterTypeName, resourceInfo.ResourceType)
}

func TestGetFirewallRules(t *testing.T) {
	firewalls := []*computepb.Firewall{{Name: to.Ptr("firewall-1")}, {Name: to.Ptr("firewall-2")}}
	fwMap := make(map[string]*computepb.Firewall)
	for _, fw := range firewalls {
		fwMap[*fw.Name] = fw
	}
	serverState := fakeServerState{firewallMap: fwMap}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	project := fakeProject
	resourceID := "resource-1"

	firewallRules, err := getFirewallRules(ctx, project, resourceID, fakeClients)

	expectedFwNames := []string{"firewall-1", "firewall-2"}

	require.NoError(t, err)
	assert.Contains(t, expectedFwNames, *firewallRules[0].Name)
	assert.Contains(t, expectedFwNames, *firewallRules[1].Name)
}

func TestGetResourceNetworkInfo(t *testing.T) {
	// Test for instance
	rInfo := &resourceInfo{Project: fakeProject, Zone: fakeZone, Name: fakeInstanceName, ResourceType: instanceTypeName, Namespace: fakeNamespace}

	instance := getFakeInstance(true)
	serverState := fakeServerState{instance: instance}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	netInfo, err := GetResourceNetworkInfo(ctx, rInfo, fakeClients)

	require.NoError(t, err)
	assert.Equal(t, convertIntIdToString(*instance.Id), netInfo.ResourceID)
	assert.Equal(t, *instance.NetworkInterfaces[0].Subnetwork, netInfo.SubnetUrl)

	// Test for cluster
	rInfo = &resourceInfo{Project: fakeProject, Region: fakeRegion, Zone: fakeZone, Name: fakeClusterName, ResourceType: clusterTypeName, Namespace: fakeNamespace}

	cluster := getFakeCluster(true)
	serverState = fakeServerState{cluster: cluster}
	fakeServer, ctx, fakeClients, fakeGRPCServer = setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	netInfo, err = GetResourceNetworkInfo(ctx, rInfo, fakeClients)

	require.NoError(t, err)
	assert.Equal(t, shortenClusterId(cluster.Id), netInfo.ResourceID)
	assert.Equal(t, fakeSubnetId, netInfo.SubnetUrl)

	// Test for service attachment
	rInfo = &resourceInfo{Project: fakeProject, Region: fakeRegion, Name: fakeClusterName, ResourceType: serviceAttachmentTypeName, Namespace: fakeNamespace}

	attachment := getFakeServiceAttachment()
	address := getFakeAddress()
	serverState = fakeServerState{serviceAttachment: attachment, address: address}
	fakeServer, ctx, fakeClients, fakeGRPCServer = setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	netInfo, err = GetResourceNetworkInfo(ctx, rInfo, fakeClients)

	require.NoError(t, err)
	assert.Equal(t, convertIntIdToString(*attachment.Id), netInfo.ResourceID)
	assert.Equal(t, *address.Address, netInfo.Address)
}

func TestIsValidResource(t *testing.T) {
	// Test for instance
	resource, fakeInstance, err := getFakeInstanceResourceDescription()
	require.NoError(t, err)

	resourceInfo, err := IsValidResource(context.Background(), resource)

	require.NoError(t, err)
	assert.Equal(t, fakeZone, resourceInfo.Zone)
	assert.Equal(t, *fakeInstance.InstanceResource.Name, resourceInfo.Name)

	// Test for cluster
	resource, fakeCluster, err := getFakeClusterResourceDescription()
	require.NoError(t, err)

	resourceInfo, err = IsValidResource(context.Background(), resource)

	require.NoError(t, err)
	assert.Equal(t, fakeZone, resourceInfo.Zone)
	assert.Equal(t, fakeCluster.Cluster.Name, resourceInfo.Name)

	// Test for service attachment
	resource, fakeService, err := getFakePSCRequest()
	require.NoError(t, err)

	resourceInfo, err = IsValidResource(context.Background(), resource)

	require.NoError(t, err)
	assert.Equal(t, fakeRegion, resourceInfo.Region)
	assert.Contains(t, fakeService.Url, resourceInfo.Name)
}

func TestReadAndProvisionResource(t *testing.T) {
	// Test for instance
	resource, instanceRequest, err := getFakeInstanceResourceDescription()
	require.NoError(t, err)

	rInfo := &resourceInfo{Project: fakeProject, Zone: fakeZone, Name: fakeInstanceName, ResourceType: instanceTypeName}
	serverState := fakeServerState{instance: getFakeInstance(true)}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	url, ip, err := ReadAndProvisionResource(ctx, resource, "subnet-1", rInfo, make([]string, 0), fakeClients)

	require.NoError(t, err)
	assert.Contains(t, url, *instanceRequest.InstanceResource.Name)
	assert.Equal(t, ip, *getFakeInstance(true).NetworkInterfaces[0].NetworkIP)

	// Test for cluster
	resource, clusterRequest, err := getFakeClusterResourceDescription()
	require.NoError(t, err)

	rInfo = &resourceInfo{Project: fakeProject, Zone: fakeZone, Name: fakeClusterName, ResourceType: clusterTypeName}

	additionalAddressSpaces := []string{"10.10.0.0/16", "10.11.0.0/16", "10.12.0.0/16"}

	url, ip, err = ReadAndProvisionResource(ctx, resource, "subnet-1", rInfo, additionalAddressSpaces, fakeClients)

	require.NoError(t, err)
	assert.Equal(t, getClusterUrl(fakeProject, fakeZone, clusterRequest.Cluster.Name), url)
	assert.Equal(t, ip, getFakeCluster(true).ClusterIpv4Cidr)

	// Test for service attachment
	serverState.address = getFakeAddress()

	resource, service, err := getFakePSCRequest()
	require.NoError(t, err)

	rInfo = &resourceInfo{Project: fakeProject, Region: fakeRegion, Name: fakeServiceAttachmentName, ResourceType: serviceAttachmentTypeName}

	url, ip, err = ReadAndProvisionResource(ctx, resource, "subnet-1", rInfo, []string{}, fakeClients)

	require.NoError(t, err)
	assert.Equal(t, service.Url, url)
	assert.Equal(t, *getFakeAddress().Address, ip)
}

func TestInstanceReadAndProvisionResource(t *testing.T) {
	instanceHandler := &instanceHandler{}
	subnet := "subnet-1"
	rInfo := &resourceInfo{Project: fakeProject, Zone: fakeZone, Name: fakeInstanceName, ResourceType: instanceTypeName}
	resource, _, err := getFakeInstanceResourceDescription()
	require.NoError(t, err)

	serverState := fakeServerState{instance: getFakeInstance(true)}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	err = instanceHandler.initClients(ctx, fakeClients)
	require.NoError(t, err)

	url, ip, err := instanceHandler.readAndProvisionResource(ctx, resource, subnet, rInfo, make([]string, 0))

	require.NoError(t, err)
	assert.Contains(t, url, *getFakeInstance(true).Name)
	assert.Equal(t, ip, *getFakeInstance(true).NetworkInterfaces[0].NetworkIP)
}

func TestInstanceGetResourceInfo(t *testing.T) {
	instanceHandler := &instanceHandler{}
	resource, instanceRequest, err := getFakeInstanceResourceDescription()
	require.NoError(t, err)

	resourceInfo, err := instanceHandler.getResourceInfo(context.Background(), resource)

	require.NoError(t, err)
	assert.Equal(t, instanceRequest.Zone, resourceInfo.Zone)
}

func TestInstanceGetNetworkInfo(t *testing.T) {
	instanceHandler := &instanceHandler{}
	rInfo := &resourceInfo{Project: fakeProject, Zone: fakeZone, Name: fakeInstanceName, ResourceType: instanceTypeName}
	instance := getFakeInstance(true)
	serverState := fakeServerState{instance: instance}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	err := instanceHandler.initClients(ctx, fakeClients)
	require.NoError(t, err)

	networkInfo, err := instanceHandler.getNetworkInfo(ctx, rInfo)

	require.NoError(t, err)
	assert.Equal(t, convertIntIdToString(*instance.Id), networkInfo.ResourceID)
	assert.Contains(t, *instance.NetworkInterfaces[0].Network, networkInfo.NetworkName)
	assert.Equal(t, *instance.NetworkInterfaces[0].Subnetwork, networkInfo.SubnetUrl)
	assert.Equal(t, *instance.NetworkInterfaces[0].NetworkIP, networkInfo.Address)
}

func TestInstanceFromResourceDecription(t *testing.T) {
	resource, instanceRequest, err := getFakeInstanceResourceDescription()
	require.NoError(t, err)

	instanceHandler := &instanceHandler{}
	instanceParsed, err := instanceHandler.fromResourceDecription(resource.Description)

	require.NoError(t, err)
	assert.Equal(t, instanceRequest.Project, instanceParsed.Project)
	assert.Equal(t, instanceRequest.InstanceResource.Id, instanceParsed.InstanceResource.Id)
}

func TestInstanceCreateWithNetwork(t *testing.T) {
	instanceHandler := &instanceHandler{}
	subnet := "subnet-1"
	instanceRequest := &computepb.InsertInstanceRequest{
		Project:          fakeProject,
		Zone:             fakeZone,
		InstanceResource: getFakeInstance(false),
	}
	rInfo := &resourceInfo{Project: fakeProject, Zone: fakeZone, Name: fakeInstanceName, ResourceType: instanceTypeName}
	serverState := fakeServerState{instance: getFakeInstance(true)}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	err := instanceHandler.initClients(ctx, fakeClients)
	require.NoError(t, err)

	url, ip, err := instanceHandler.createWithNetwork(ctx, instanceRequest, subnet, rInfo)

	require.NoError(t, err)
	assert.Contains(t, url, *instanceRequest.InstanceResource.Name)
	assert.Equal(t, ip, *getFakeInstance(true).NetworkInterfaces[0].NetworkIP)

}

func TestClusterReadAndProvisionResource(t *testing.T) {
	clusterHandler := &clusterHandler{}
	resource, clusterRequest, err := getFakeClusterResourceDescription()
	require.NoError(t, err)

	rInfo := &resourceInfo{Project: fakeProject, Zone: fakeZone, Name: fakeClusterName, ResourceType: clusterTypeName}

	serverState := fakeServerState{}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	err = clusterHandler.initClients(ctx, fakeClients)
	require.NoError(t, err)

	additionalAddressSpaces := []string{"10.10.0.0/16", "10.11.0.0/16", "10.12.0.0/16"}

	url, ip, err := clusterHandler.readAndProvisionResource(ctx, resource, "subnet-1", rInfo, additionalAddressSpaces)

	require.NoError(t, err)
	assert.Equal(t, getClusterUrl(fakeProject, fakeZone, clusterRequest.Cluster.Name), url)
	assert.Equal(t, ip, getFakeCluster(true).ClusterIpv4Cidr)
}

func TestClusterGetResourceInfo(t *testing.T) {
	clusterHandler := &clusterHandler{}
	resource, _, err := getFakeClusterResourceDescription()
	require.NoError(t, err)

	resourceInfo, err := clusterHandler.getResourceInfo(context.Background(), resource)

	require.NoError(t, err)
	assert.Equal(t, fakeZone, resourceInfo.Zone)
	assert.Equal(t, clusterTypeName, resourceInfo.ResourceType)
}

func TestClusterGetNetworkInfo(t *testing.T) {
	clusterHandler := &clusterHandler{}
	resourceInfo := &resourceInfo{Project: fakeProject, Region: fakeRegion, Zone: fakeZone, Name: fakeClusterName, ResourceType: clusterTypeName}
	cluster := getFakeCluster(true)
	serverState := fakeServerState{cluster: cluster}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	err := clusterHandler.initClients(ctx, fakeClients)
	require.NoError(t, err)

	networkInfo, err := clusterHandler.getNetworkInfo(ctx, resourceInfo)

	require.NoError(t, err)
	assert.Equal(t, shortenClusterId(cluster.Id), networkInfo.ResourceID)
	assert.Equal(t, fakeSubnetId, networkInfo.SubnetUrl)
}

func TestClusterFromResourceDecription(t *testing.T) {
	resource, clusterRequest, err := getFakeClusterResourceDescription()
	require.NoError(t, err)

	clusterHandler := &clusterHandler{}
	clusterParsed, err := clusterHandler.fromResourceDecription(resource.Description)

	require.NoError(t, err)
	assert.Equal(t, clusterRequest.Cluster.Id, clusterParsed.Cluster.Id)
}

func TestClusterCreateWithNetwork(t *testing.T) {
	clusterHandler := &clusterHandler{}
	subnet := "subnet-1"
	clusterRequest := &containerpb.CreateClusterRequest{
		Cluster: getFakeCluster(false),
	}
	rInfo := &resourceInfo{Project: fakeProject, Zone: fakeZone, Name: fakeClusterName, ResourceType: clusterTypeName}
	serverState := fakeServerState{}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	err := clusterHandler.initClients(ctx, fakeClients)
	require.NoError(t, err)

	additionalAddressSpaces := []string{"10.10.0.0/16", "10.11.0.0/16", "10.12.0.0/16"}

	url, ip, err := clusterHandler.createWithNetwork(ctx, clusterRequest, subnet, rInfo, additionalAddressSpaces)

	require.NoError(t, err)
	assert.Equal(t, getClusterUrl(fakeProject, fakeZone, fakeClusterName), url)
	assert.Equal(t, ip, getFakeCluster(true).ClusterIpv4Cidr)
}

func TestPrivateServiceReadAndProvisionResource(t *testing.T) {
	pscHandler := &privateServiceHandler{}
	resource, service, err := getFakePSCRequest()
	require.NoError(t, err)

	rInfo := &resourceInfo{Project: fakeProject, Region: fakeRegion, Name: fakeServiceAttachmentName, ResourceType: serviceAttachmentTypeName}

	serverState := fakeServerState{address: getFakeAddress()}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	err = pscHandler.initClients(ctx, fakeClients)
	require.NoError(t, err)

	url, ip, err := pscHandler.readAndProvisionResource(ctx, resource, "subnet-1", rInfo, []string{})

	require.NoError(t, err)
	assert.Equal(t, service.Url, url)
	assert.Equal(t, ip, *getFakeAddress().Address)
}

func TestPrivateServiceGetResourceInfo(t *testing.T) {
	pscHandler := &privateServiceHandler{}
	resource, _, err := getFakePSCRequest()
	require.NoError(t, err)

	resourceInfo, err := pscHandler.getResourceInfo(context.Background(), resource)

	require.NoError(t, err)
	assert.Equal(t, fakeRegion, resourceInfo.Region)
	assert.Equal(t, serviceAttachmentTypeName, resourceInfo.ResourceType)
	assert.Equal(t, fakeServiceAttachmentName, resourceInfo.Name)
}

func TestPrivateServiceGetNetworkInfo(t *testing.T) {
	pscHandler := &privateServiceHandler{}
	resourceInfo := &resourceInfo{Project: fakeProject, Region: fakeRegion, Zone: fakeZone, Name: fakeServiceAttachmentName, ResourceType: serviceAttachmentTypeName}

	attachment := getFakeServiceAttachment()
	address := getFakeAddress()
	serverState := fakeServerState{serviceAttachment: attachment, address: address}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	err := pscHandler.initClients(ctx, fakeClients)
	require.NoError(t, err)

	networkInfo, err := pscHandler.getNetworkInfo(ctx, resourceInfo)

	require.NoError(t, err)
	assert.Equal(t, convertIntIdToString(*attachment.Id), networkInfo.ResourceID)
	assert.Equal(t, *address.Address, networkInfo.Address)
}

func TestPrivateServiceCreateWithNetwork(t *testing.T) {
	pscHandler := &privateServiceHandler{}
	subnet := "subnet-1"
	serviceDescription := &ServiceAttachmentDescription{Url: fakeServiceAttachmentUrl}

	rInfo := &resourceInfo{Project: fakeProject, Region: fakeRegion, Name: fakeServiceAttachmentName, ResourceType: serviceAttachmentTypeName}
	serverState := fakeServerState{address: getFakeAddress()}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &serverState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	err := pscHandler.initClients(ctx, fakeClients)
	require.NoError(t, err)

	url, ip, err := pscHandler.createWithNetwork(ctx, *serviceDescription, subnet, rInfo)

	require.NoError(t, err)
	assert.Equal(t, fakeServiceAttachmentUrl, url)
	assert.Equal(t, *getFakeAddress().Address, ip)
}
