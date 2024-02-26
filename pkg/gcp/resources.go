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
	"strconv"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	container "cloud.google.com/go/container/apiv1"
	containerpb "cloud.google.com/go/container/apiv1/containerpb"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
	"google.golang.org/protobuf/proto"
)

const (
	clusterTypeName  = "cluster"
	instanceTypeName = "instance"
)

var (
	supportedResourceTypes = map[string]bool{clusterTypeName: true, instanceTypeName: true}
)

func resourceIsInNamespace(network string, namespace string) bool {
	return strings.HasSuffix(network, getVpcName(namespace))
}

// Gets a GCP network tag for a GCP instance
func getNetworkTag(namespace string, resourceType string, resourceId string) string {
	return getInvisinetsNamespacePrefix(namespace) + "-" + resourceType + "-" + resourceId
}

type ResourceInfo struct {
	name         string
	project      string
	zone         string
	region       string
	namespace    string
	resourceType string
}

// TODO: Maybe move back to plugin.go
func getFirewallRules(ctx context.Context, client *compute.FirewallsClient, project string, resourceID string) ([]*computepb.Firewall, error) {
	firewallRules := []*computepb.Firewall{}
	filter := fmt.Sprintf("name:%s", getFirewallName("", resourceID))
	listFirewallsRequest := &computepb.ListFirewallsRequest{ // Don't think we can filtler on targets since they are a list -- maybe filter on the name?
		Project: project,
		Filter:  &filter,
	}
	firewallIterator := client.List(ctx, listFirewallsRequest)

	for {
		firewallRule, err := firewallIterator.Next()
		if firewallRule == nil {
			break
		}
		if err != nil {
			return nil, err
		}
		// if strings.Contains(firewallRule.GetName(), getFirewallRuleName()) {
		// 	firewallRules = append(firewallRules, firewallRule)
		// }
	}
	return firewallRules, nil
}

func parseResourceUri(resourceUri string) (*ResourceInfo, error) {
	parsedResourceId := parseGCPURL(instanceId)
	if name, ok := parsedResourceId["instances"]; ok {
		return &ResourceInfo{project: parsedResourceId["projects"], zone: parsedResourceId["zones"], name: name, resourceType: instanceTypeName}, nil
	} else if name, ok := parsedResourceId["clusters"]; ok {
		return &ResourceInfo{project: parsedResourceId["projects"], zone: parsedResourceId["zones"], name: name, resourceType: clusterTypeName}, nil
	}
	return nil, fmt.Errorf("unable to parse resource URI")
}

// Returns (subnet URI, resource ID, error)
func getResourceParams(ctx context.Context, instancesClient *compute.InstancesClient, clusterClient *container.ClusterManagerClient, resourceInfo *ResourceInfo) (*string, *string, error) {
	if resourceInfo.namespace == "" {
		return nil, nil, fmt.Errorf("namespace is empty")
	}

	var networkName string
	var subnetURI string
	var resourceID string
	if resourceInfo.resourceType == instanceTypeName {
		instanceRequest := &computepb.GetInstanceRequest{
			Instance: resourceInfo.name,
			Project:  resourceInfo.project,
			Zone:     resourceInfo.zone,
		}
		instanceResponse, err := instancesClient.Get(ctx, instanceRequest)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get instance: %w", err)
		}
		networkName = *instanceResponse.NetworkInterfaces[0].Network
		subnetURI = *instanceResponse.NetworkInterfaces[0].Subnetwork
		resourceID = strconv.FormatUint(*instanceResponse.Id, 16)
	} else if resourceInfo.resourceType == clusterTypeName {
		clusterRequest := &containerpb.GetClusterRequest{
			ProjectId: resourceInfo.project,
			Zone:      resourceInfo.zone,
			ClusterId: resourceInfo.name,
		}
		clusterResponse, err := clusterClient.GetCluster(ctx, clusterRequest)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get cluster: %w", err)
		}
		networkName = clusterResponse.Network
		subnetURI = clusterResponse.Subnetwork
		resourceID = clusterResponse.Id
	} else {
		return nil, nil, fmt.Errorf("unknown resource type")
	}
	if !resourceIsInNamespace(networkName, resourceInfo.namespace) {
		return nil, nil, fmt.Errorf("instance is not in namespace")
	}
	return &subnetURI, &resourceID, nil
}

func IsValidResource(ctx context.Context, resource *invisinetspb.ResourceDescription) (*ResourceInfo, error) {
	// Determine type based on whether it unmarshals correctly??
	insertInstanceRequest := &computepb.InsertInstanceRequest{}
	createClusterRequest := &containerpb.CreateClusterRequest{}
	err := json.Unmarshal(resource.Description, insertInstanceRequest)
	if err == nil {
		return &ResourceInfo{project: insertInstanceRequest.Project, zone: insertInstanceRequest.Zone, name: *insertInstanceRequest.InstanceResource.Name}, nil
	} else if err := json.Unmarshal(resource.Description, createClusterRequest); err == nil {
		project := strings.Split(createClusterRequest.Parent, "/")[1]
		zone := strings.Split(createClusterRequest.Parent, "/")[4]
		return &ResourceInfo{project: project, zone: zone, name: createClusterRequest.Cluster.Name}, nil
	} else {
		return nil, fmt.Errorf("resource description contains unknown GCP resource")
	}
}

func ReadAndProvisionResource(ctx context.Context, resource *invisinetspb.ResourceDescription, subnetName string, resourceInfo *ResourceInfo, instanceClient *compute.InstancesClient, clusterClient *container.ClusterManagerClient) (string, string, error) {
	// Determine type based on whether it unmarshals correctly??
	insertInstanceRequest := &computepb.InsertInstanceRequest{}
	createClusterRequest := &containerpb.CreateClusterRequest{}
	err := json.Unmarshal(resource.Description, insertInstanceRequest)
	if err == nil {
		handler := &GCPInstance{}
		vm, err := handler.FromResourceDecription(resource.Description)
		if err != nil {
			return "", "", err
		}
		return handler.CreateWithNetwork(ctx, vm, subnetName, resourceInfo, instanceClient)
	} else if err := json.Unmarshal(resource.Description, createClusterRequest); err == nil {
		handler := &GKE{}
		aks, err := handler.FromResourceDecription(resource.Description)
		if err != nil {
			return "", "", err
		}
		return handler.CreateWithNetwork(ctx, aks, subnetName, resourceInfo, clusterClient)
	} else {
		return "", "", fmt.Errorf("resource description contains unknown Azure resource")
	}

	return "", "", nil
}

type GCPResourceHandler[T any] interface {
	CreateWithNetwork(ctx context.Context, resource *T, subnet computepb.Subnetwork, resourceInfo *ResourceInfo, client any) (string, string, error)
	FromResourceDecription(resourceDesc []byte) (T, error)
}

type GCPInstance struct {
	GCPResourceHandler[computepb.InsertInstanceRequest]
}

func (r *GCPInstance) CreateWithNetwork(ctx context.Context, instance *computepb.InsertInstanceRequest, subnetName string, resourceInfo *ResourceInfo, client *compute.InstancesClient) (string, string, error) {
	// Configure network settings to Invisinets VPC and corresponding subnet
	instance.InstanceResource.NetworkInterfaces = []*computepb.NetworkInterface{
		{
			Network:    proto.String(GetVpcUri(resourceInfo.namespace)),
			Subnetwork: proto.String("regions/" + resourceInfo.region + "/subnetworks/" + subnetName),
		},
	}

	// Insert instance
	insertInstanceOp, err := client.Insert(ctx, instance)
	if err != nil {
		return "", "", fmt.Errorf("unable to insert instance: %w", err)
	}
	if err = insertInstanceOp.Wait(ctx); err != nil {
		return "", "", fmt.Errorf("unable to wait for the operation: %w", err)
	}

	// Add network tag which will be used by GCP firewall rules corresponding to Invisinets permit list rules
	// The instance is fetched again as the Id which is used to create the tag is only available after instance creation
	instanceName := *instance.InstanceResource.Name
	getInstanceReq := &computepb.GetInstanceRequest{
		Instance: instanceName,
		Project:  resourceInfo.project,
		Zone:     resourceInfo.zone,
	}
	getInstanceResp, err := client.Get(ctx, getInstanceReq)
	if err != nil {
		return "", "", fmt.Errorf("unable to get instance: %w", err)
	}
	setTagsReq := &computepb.SetTagsInstanceRequest{
		Instance: instanceName,
		Project:  resourceInfo.project,
		Zone:     resourceInfo.zone,
		TagsResource: &computepb.Tags{
			Items:       append(getInstanceResp.Tags.Items, getNetworkTagInstance(resourceInfo.namespace, *getInstanceResp.Id)),
			Fingerprint: getInstanceResp.Tags.Fingerprint,
		},
	}
	setTagsOp, err := client.SetTags(ctx, setTagsReq)
	if err != nil {
		return "", "", fmt.Errorf("unable to set tags: %w", err)
	}
	if err = setTagsOp.Wait(ctx); err != nil {
		return "", "", fmt.Errorf("unable to wait for the operation")
	}

	return getInstanceUri(resourceInfo.project, resourceInfo.zone, instanceName), *getInstanceResp.NetworkInterfaces[0].NetworkIP, nil
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

func (r *GKE) CreateWithNetwork(ctx context.Context, cluster *containerpb.CreateClusterRequest, subnetName string, resourceInfo *ResourceInfo, client *container.ClusterManagerClient) (string, string, error) {
	// Add subnet to the cluster description and provision
	// Add tags to the cluster subnet?
	// Configure network settings to Invisinets VPC and corresponding subnet
	cluster.Cluster.Network = GetVpcUri(resourceInfo.namespace)
	cluster.Cluster.Subnetwork = "regions/" + resourceInfo.region + "/subnetworks/" + subnetName

	// Create the cluster
	_, err := client.CreateCluster(ctx, cluster)
	if err != nil {
		return "", "", fmt.Errorf("unable to insert instance: %w", err)
	}
	// TODO now: what to do with the cluster response?

	// Add network tag which will be used by GCP firewall rules corresponding to Invisinets permit list rules
	// The cluster is fetched again as the Id which is used to create the tag is only available after instance creation
	getClusterRequest := &containerpb.GetClusterRequest{
		ProjectId: resourceInfo.project,
		Zone:      resourceInfo.zone,
		ClusterId: cluster.Cluster.Name,
	}
	getClusterResp, err := client.GetCluster(ctx, getClusterRequest)
	if err != nil {
		return "", "", fmt.Errorf("unable to get instance: %w", err)
	}
	updateClusterRequest := &containerpb.UpdateClusterRequest{
		ProjectId: resourceInfo.project,
		Zone:      resourceInfo.zone,
		Name:      cluster.Cluster.Name,
		Update: &containerpb.ClusterUpdate{
			DesiredNodePoolAutoConfigNetworkTags: &containerpb.NetworkTags{
				Tags: append(getClusterResp.NodePools[0].Config.Tags, getNetworkTagCluster(resourceInfo.namespace, getClusterResp.Id)),
			},
		},
	}
	_, err = client.UpdateCluster(ctx, updateClusterRequest)
	if err != nil {
		return "", "", fmt.Errorf("unable to set tags: %w", err)
	}

	// TODO now: is this the cluster URI?
	return getClusterResp.Id, *&getClusterResp.ClusterIpv4Cidr, nil
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
