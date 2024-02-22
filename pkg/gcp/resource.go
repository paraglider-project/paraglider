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

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	container "cloud.google.com/go/container/apiv1"
	containerpb "cloud.google.com/go/container/apiv1/containerpb"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
	"google.golang.org/protobuf/proto"
)

func ReadAndProvisionResource(ctx context.Context, resource *invisinetspb.ResourceDescription, subnet *armnetwork.Subnet, resourceInfo *ResourceIDInfo, sdkHandler AzureSDKHandler) (string, error) {
	// Determine type based on whether it unmarshals correctly??

}

type GCPResourceHandler[T any] interface {
	CreateWithNetwork(ctx context.Context, resource *T, subnet computepb.Subnetwork) (string, error)
	FromResourceDecription(resourceDesc []byte) (T, error)
}

type GCPInstance struct {
	GCPResourceHandler[computepb.InsertInstanceRequest]
}

func (r *GCPInstance) CreateWithNetwork(ctx context.Context, instance *computepb.InsertInstanceRequest, subnet *computepb.Subnetwork, resourceInfo *ResourceInfo, instancesClient *compute.InstancesClient) (string, error) {
	// Configure network settings to Invisinets VPC and corresponding subnet
	instance.InstanceResource.NetworkInterfaces = []*computepb.NetworkInterface{
		{
			Network:    proto.String(GetVpcUri(resourceInfo.Namespace)),
			Subnetwork: proto.String("regions/" + resourceInfo.region + "/subnetworks/" + resourceInfo.subnetName),
		},
	}

	// Insert instance
	insertInstanceOp, err := instancesClient.Insert(ctx, instance)
	if err != nil {
		return "", fmt.Errorf("unable to insert instance: %w", err)
	}
	if err = insertInstanceOp.Wait(ctx); err != nil {
		return "", fmt.Errorf("unable to wait for the operation: %w", err)
	}

	// Add network tag which will be used by GCP firewall rules corresponding to Invisinets permit list rules
	// The instance is fetched again as the Id which is used to create the tag is only available after instance creation
	instanceName := *instance.InstanceResource.Name
	getInstanceReq := &computepb.GetInstanceRequest{
		Instance: instanceName,
		Project:  resourceInfo.project,
		Zone:     resourceInfo.zone,
	}
	getInstanceResp, err := instancesClient.Get(ctx, getInstanceReq)
	if err != nil {
		return "", fmt.Errorf("unable to get instance: %w", err)
	}
	setTagsReq := &computepb.SetTagsInstanceRequest{
		Instance: instanceName,
		Project:  resourceInfo.project,
		Zone:     resourceInfo.zone,
		TagsResource: &computepb.Tags{
			Items:       append(getInstanceResp.Tags.Items, getNetworkTag(resourceInfo.Namespace, *getInstanceResp.Id)),
			Fingerprint: getInstanceResp.Tags.Fingerprint,
		},
	}
	setTagsOp, err := instancesClient.SetTags(ctx, setTagsReq)
	if err != nil {
		return "", fmt.Errorf("unable to set tags: %w", err)
	}
	if err = setTagsOp.Wait(ctx); err != nil {
		return "", fmt.Errorf("unable to wait for the operation")
	}

	return *getInstanceResp.NetworkInterfaces[0].NetworkIP, nil
}

func (r *GCPInstance) FromResourceDecription(resourceDesc []byte) (*computepb.InsertInstanceRequest, error) {
	insertInstanceRequest := &computepb.InsertInstanceRequest{}
	err := json.Unmarshal(resourceDesc, insertInstanceRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource description: %w", err)
	}
	if len(insertInstanceRequest.InstanceResource.NetworkInterfaces) != 0 {
		return nil, fmt.Errorf("network settings should not be specified")
	}
	return insertInstanceRequest, nil
}

type GKE struct {
	GCPResourceHandler[containerpb.CreateClusterRequest]
}

func (r *GKE) CreateWithNetwork(ctx context.Context, cluster *containerpb.CreateClusterRequest, subnet *computepb.Subnetwork, resourceInfo *ResourceInfo, containerClient *container.ClusterManagerClient) (string, error) {
	// Add subnet to the cluster description and provision
	// Add tags to the cluster subnet?
	// Configure network settings to Invisinets VPC and corresponding subnet
	cluster.Cluster.Network = GetVpcUri(resourceInfo.Namespace)
	cluster.Cluster.Subnetwork = "regions/" + resourceInfo.region + "/subnetworks/" + resourceInfo.subnetName

	// Create the cluster
	_, err := containerClient.CreateCluster(ctx, cluster)
	if err != nil {
		return "", fmt.Errorf("unable to insert instance: %w", err)
	}
	// TODO now: what to do with the cluster response?

	// Add network tag which will be used by GCP firewall rules corresponding to Invisinets permit list rules
	// The cluster is fetched again as the Id which is used to create the tag is only available after instance creation
	getClusterRequest := &containerpb.GetClusterRequest{
		ProjectId: resourceInfo.project,
		Zone:      resourceInfo.zone,
		ClusterId: cluster.Cluster.Name,
	}
	getClusterResp, err := containerClient.GetCluster(ctx, getClusterRequest)
	if err != nil {
		return "", fmt.Errorf("unable to get instance: %w", err)
	}
	updateClusterRequest := &containerpb.UpdateClusterRequest{
		ProjectId: resourceInfo.project,
		Zone:      resourceInfo.zone,
		Name:      cluster.Cluster.Name,
		Update: &containerpb.ClusterUpdate{
			DesiredNodePoolAutoConfigNetworkTags: &containerpb.NetworkTags{
				Tags: append(getClusterResp.NodePools[0].Config.Tags, getNetworkTag(resourceInfo.Namespace, getClusterResp.Id)),
			},
		},
	}
	_, err = containerClient.UpdateCluster(ctx, updateClusterRequest)
	if err != nil {
		return "", fmt.Errorf("unable to set tags: %w", err)
	}

	return *&getClusterResp.ClusterIpv4Cidr, nil
}

func (r *GKE) FromResourceDecription(resourceDesc []byte) (*containerpb.CreateClusterRequest, error) {
	createClusterRequest := &containerpb.CreateClusterRequest{}
	err := json.Unmarshal(resourceDesc, createClusterRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource description: %w", err)
	}
	if createClusterRequest.Cluster.Network == "" {
		return nil, fmt.Errorf("network settings should not be specified")
	}
	return createClusterRequest, nil
}
