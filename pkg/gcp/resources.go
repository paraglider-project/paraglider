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
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	container "cloud.google.com/go/container/apiv1"
	containerpb "cloud.google.com/go/container/apiv1/containerpb"
	"github.com/paraglider-project/paraglider/pkg/paragliderpb"
	"google.golang.org/protobuf/proto"
)

const (
	clusterTypeName   = "cluster"
	instanceTypeName  = "instance"
	clusterNameFormat = "projects/%s/locations/%s/clusters/%s"
)

type resourceInfo struct {
	Name                       string
	Project                    string
	Zone                       string
	Region                     string
	Namespace                  string
	ResourceType               string
	CreatesOwnSubnet           bool
	NumAdditionalAddressSpaces int
}

type resourceNetworkInfo struct {
	SubnetUrl   string
	ResourceID  string
	NetworkName string
}

func resourceIsInNamespace(network string, namespace string) bool {
	return strings.HasSuffix(network, getVpcName(namespace))
}

// Gets a GCP network tag for a GCP instance
func getNetworkTag(namespace string, resourceType string, resourceId string) string {
	return getParagliderNamespacePrefix(namespace) + "-" + resourceType + "-" + resourceId
}

func convertInstanceIdToString(instanceId uint64) string {
	id := strconv.FormatUint(instanceId, 16)
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func shortenClusterId(clusterId string) string {
	return clusterId[:8]
}

func getClusterNodeTag(namespace string, clusterName string, clusterId string) string {
	return getParagliderNamespacePrefix(namespace) + "-gke-" + clusterName + "-" + shortenClusterId(clusterId) + "-node"
}

// Get the firewall rules associated with a resource following the naming convention
func getFirewallRules(ctx context.Context, client *compute.FirewallsClient, project string, resourceID string) ([]*computepb.Firewall, error) {
	firewallRules := []*computepb.Firewall{}
	filter := fmt.Sprintf("name eq \".*%s.*\"", resourceID)
	listFirewallsRequest := &computepb.ListFirewallsRequest{
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
		firewallRules = append(firewallRules, firewallRule)
	}
	return firewallRules, nil
}

// parseResourceUrl parses the resource URL and returns information about the resource (such as project, zone, name, and type)
func parseResourceUrl(resourceUrl string) (*resourceInfo, error) {
	parsedResourceId := parseUrl(resourceUrl)
	if name, ok := parsedResourceId["instances"]; ok {
		return &resourceInfo{Project: parsedResourceId["projects"], Zone: parsedResourceId["zones"], Region: getRegionFromZone(parsedResourceId["zones"]), Name: name, ResourceType: instanceTypeName}, nil
	} else if name, ok := parsedResourceId["clusters"]; ok {
		return &resourceInfo{Project: parsedResourceId["projects"], Zone: parsedResourceId["locations"], Region: getRegionFromZone(parsedResourceId["locations"]), Name: name, ResourceType: clusterTypeName}, nil
	}
	return nil, fmt.Errorf("unable to parse resource URL")
}

// Get the resource handler for a given resource type with the client field set
func getResourceHandlerWithClient(resourceType string, instancesClient *compute.InstancesClient, clusterClient *container.ClusterManagerClient) (iGCPResourceHandler, error) {
	if resourceType == instanceTypeName {
		handler := &gcpInstance{}
		handler.client = instancesClient
		return handler, nil
	} else if resourceType == clusterTypeName {
		handler := &gcpGKE{}
		handler.client = clusterClient
		return handler, nil
	} else {
		return nil, fmt.Errorf("unknown resource type")
	}
}

// Get the resource handler for a given resource description, the handler will not have a client
func getResourceHandlerFromDescription(resourceDesc []byte) (iGCPResourceHandler, error) {
	insertInstanceRequest := &computepb.InsertInstanceRequest{}
	createClusterRequest := &containerpb.CreateClusterRequest{}
	err := json.Unmarshal(resourceDesc, insertInstanceRequest)
	if err == nil && insertInstanceRequest.InstanceResource != nil {
		return &gcpInstance{}, nil
	} else if err := json.Unmarshal(resourceDesc, createClusterRequest); err == nil && createClusterRequest.Cluster != nil {
		return &gcpGKE{}, nil
	} else {
		return nil, fmt.Errorf("resource description contains unknown GCP resource")
	}
}

// Gets network information about a resource and confirms it is in the correct namespace
// Returns the subnet URL and resource ID (instance ID or cluster ID, not URL since this is used for firewall rule naming)
func GetResourceNetworkInfo(ctx context.Context, instancesClient *compute.InstancesClient, clusterClient *container.ClusterManagerClient, resourceInfo *resourceInfo) (*string, *string, error) {
	if resourceInfo.Namespace == "" {
		return nil, nil, fmt.Errorf("namespace is empty")
	}

	handler, err := getResourceHandlerWithClient(resourceInfo.ResourceType, instancesClient, clusterClient)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get resource handler: %w", err)
	}
	netInfo, err := handler.getNetworkInfo(ctx, resourceInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get network info: %w", err)
	}

	if !resourceIsInNamespace(netInfo.NetworkName, resourceInfo.Namespace) {
		return nil, nil, fmt.Errorf("resource is not in namespace")
	}
	return &netInfo.SubnetUrl, &netInfo.ResourceID, nil
}

// Determine whether the provided resource description is supported
func IsValidResource(ctx context.Context, resource *paragliderpb.CreateResourceRequest) (*resourceInfo, error) {
	handler, err := getResourceHandlerFromDescription(resource.Description)
	if err != nil {
		return nil, fmt.Errorf("unable to get resource handler: %w", err)
	}
	resourceInfo, err := handler.getResourceInfo(ctx, resource)
	if err != nil {
		return nil, fmt.Errorf("unable to get resource info: %w", err)
	}
	return resourceInfo, nil
}

// Read the resource description and provision the resource
func ReadAndProvisionResource(ctx context.Context, resource *paragliderpb.CreateResourceRequest, subnetName string, resourceInfo *resourceInfo, instanceClient *compute.InstancesClient, clusterClient *container.ClusterManagerClient, firewallsClient *compute.FirewallsClient, additionalAddrSpaces []string) (string, string, error) {
	handler, err := getResourceHandlerWithClient(resourceInfo.ResourceType, instanceClient, clusterClient)
	if err != nil {
		return "", "", fmt.Errorf("unable to get resource handler: %w", err)
	}
	return handler.readAndProvisionResource(ctx, resource, subnetName, resourceInfo, firewallsClient, additionalAddrSpaces)
}

// Type defition for supported resources
type supportedGCPResourceClient interface {
	compute.InstancesClient | container.ClusterManagerClient
}

// Interface to implement to support a resource
type iGCPResourceHandler interface {
	// Read and provision the resource with the provided subnet
	readAndProvisionResource(ctx context.Context, resource *paragliderpb.CreateResourceRequest, subnetName string, resourceInfo *resourceInfo, firewallsClient *compute.FirewallsClient, additionalAddrSpaces []string) (string, string, error)
	// Get network information about the resource
	getNetworkInfo(ctx context.Context, resourceInfo *resourceInfo) (*resourceNetworkInfo, error)
	// Get information about the reosurce from the resource description
	getResourceInfo(ctx context.Context, resource *paragliderpb.CreateResourceRequest) (*resourceInfo, error)
}

// Generic GCP resource handler
type gcpResourceHandler[T supportedGCPResourceClient] struct {
	iGCPResourceHandler
	client *T
}

// GCP instance resource handler
type gcpInstance struct {
	gcpResourceHandler[compute.InstancesClient]
}

// Get the resource information for a GCP instance
func (r *gcpInstance) getResourceInfo(ctx context.Context, resource *paragliderpb.CreateResourceRequest) (*resourceInfo, error) {
	insertInstanceRequest := &computepb.InsertInstanceRequest{}
	err := json.Unmarshal(resource.Description, insertInstanceRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource description: %w", err)
	}
	return &resourceInfo{Zone: insertInstanceRequest.Zone, NumAdditionalAddressSpaces: r.getNumberAddressSpacesRequired(), ResourceType: instanceTypeName}, nil
}

// Read and provision a GCP instance
func (r *gcpInstance) readAndProvisionResource(ctx context.Context, resource *paragliderpb.CreateResourceRequest, subnetName string, resourceInfo *resourceInfo, firewallsClient *compute.FirewallsClient, additionalAddrSpaces []string) (string, string, error) {
	vm, err := r.fromResourceDecription(resource.Description)
	if err != nil {
		return "", "", err
	}
	return r.createWithNetwork(ctx, vm, subnetName, resourceInfo, firewallsClient)
}

// Get the subnet requirements for a GCP instance
func (r *gcpInstance) getNumberAddressSpacesRequired() int {
	return 0
}

// Get network information about a GCP instance
// Returns the network name, subnet URL, and instance ID converted to a string for rule naming
func (r *gcpInstance) getNetworkInfo(ctx context.Context, resourceInfo *resourceInfo) (*resourceNetworkInfo, error) {
	instanceRequest := &computepb.GetInstanceRequest{
		Instance: resourceInfo.Name,
		Project:  resourceInfo.Project,
		Zone:     resourceInfo.Zone,
	}
	instanceResponse, err := r.client.Get(ctx, instanceRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to get instance: %w", err)
	}
	networkName := *instanceResponse.NetworkInterfaces[0].Network
	subnetUrl := *instanceResponse.NetworkInterfaces[0].Subnetwork
	resourceID := convertInstanceIdToString(*instanceResponse.Id)
	return &resourceNetworkInfo{NetworkName: networkName, SubnetUrl: subnetUrl, ResourceID: resourceID}, nil
}

// Create a GCP instance with network settings
// Returns the instance URL and instance IP
func (r *gcpInstance) createWithNetwork(ctx context.Context, instance *computepb.InsertInstanceRequest, subnetName string, resourceInfo *resourceInfo, firewallsClient *compute.FirewallsClient) (string, string, error) {
	// Set project and name
	instance.Project = resourceInfo.Project
	instance.InstanceResource.Name = proto.String(resourceInfo.Name)

	// Configure network settings to Paraglider VPC and corresponding subnet
	instance.InstanceResource.NetworkInterfaces = []*computepb.NetworkInterface{
		{
			Network:    proto.String(GetVpcUrl(resourceInfo.Project, resourceInfo.Namespace)),
			Subnetwork: proto.String(getSubnetworkUrl(resourceInfo.Project, resourceInfo.Region, subnetName)),
		},
	}

	// Insert instance
	insertInstanceOp, err := r.client.Insert(ctx, instance)
	if err != nil {
		return "", "", fmt.Errorf("unable to insert instance: %w", err)
	}
	if err = insertInstanceOp.Wait(ctx); err != nil {
		return "", "", fmt.Errorf("unable to wait for the operation: %w", err)
	}

	// Add network tag which will be used by GCP firewall rules corresponding to Paraglider permit list rules
	// The instance is fetched again as the Id which is used to create the tag is only available after instance creation
	instanceName := *instance.InstanceResource.Name
	getInstanceReq := &computepb.GetInstanceRequest{
		Instance: instanceName,
		Project:  resourceInfo.Project,
		Zone:     resourceInfo.Zone,
	}

	getInstanceResp, err := r.client.Get(ctx, getInstanceReq)
	if err != nil {
		return "", "", fmt.Errorf("unable to get instance: %w", err)
	}
	existingTags := []string{}
	if getInstanceResp.Tags != nil {
		existingTags = getInstanceResp.Tags.Items
	}
	setTagsReq := &computepb.SetTagsInstanceRequest{
		Instance: instanceName,
		Project:  resourceInfo.Project,
		Zone:     resourceInfo.Zone,
		TagsResource: &computepb.Tags{
			Items:       append(existingTags, getNetworkTag(resourceInfo.Namespace, instanceTypeName, convertInstanceIdToString(*getInstanceResp.Id))),
			Fingerprint: getInstanceResp.Tags.Fingerprint,
		},
	}
	setTagsOp, err := r.client.SetTags(ctx, setTagsReq)
	if err != nil {
		return "", "", fmt.Errorf("unable to set tags: %w", err)
	}
	if err = setTagsOp.Wait(ctx); err != nil {
		return "", "", fmt.Errorf("unable to wait for the operation")
	}

	return getInstanceUrl(resourceInfo.Project, resourceInfo.Zone, instanceName), *getInstanceResp.NetworkInterfaces[0].NetworkIP, nil
}

// Parse the resource description and return the instance request
func (r *gcpInstance) fromResourceDecription(resourceDesc []byte) (*computepb.InsertInstanceRequest, error) {
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

// GCP cluster resource handler
type gcpGKE struct {
	gcpResourceHandler[container.ClusterManagerClient]
}

// Read and provision a GCP cluster
func (r *gcpGKE) readAndProvisionResource(ctx context.Context, resource *paragliderpb.CreateResourceRequest, subnetName string, resourceInfo *resourceInfo, firewallsClient *compute.FirewallsClient, additionalAddrSpaces []string) (string, string, error) {
	gke, err := r.fromResourceDecription(resource.Description)
	if err != nil {
		return "", "", err
	}
	return r.createWithNetwork(ctx, gke, subnetName, resourceInfo, firewallsClient, additionalAddrSpaces)
}

// Get the resource information for a GCP cluster
func (r *gcpGKE) getResourceInfo(ctx context.Context, resource *paragliderpb.CreateResourceRequest) (*resourceInfo, error) {
	createClusterRequest := &containerpb.CreateClusterRequest{}
	err := json.Unmarshal(resource.Description, createClusterRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource description: %w", err)
	}
	zone := strings.Split(createClusterRequest.Parent, "/")[3]
	return &resourceInfo{Zone: zone, NumAdditionalAddressSpaces: r.getNumberAddressSpacesRequired(), ResourceType: clusterTypeName}, nil
}

// Get the subnet requirements for a GCP instance
func (r *gcpGKE) getNumberAddressSpacesRequired() int {
	return 3
}

// Get network information about a GCP cluster
// Returns the subnet URL and resource ID (cluster ID, not URL since this is used for firewall rule naming)
func (r *gcpGKE) getNetworkInfo(ctx context.Context, resourceInfo *resourceInfo) (*resourceNetworkInfo, error) {
	clusterRequest := &containerpb.GetClusterRequest{
		Name: fmt.Sprintf(clusterNameFormat, resourceInfo.Project, resourceInfo.Zone, resourceInfo.Name),
	}
	clusterResponse, err := r.client.GetCluster(ctx, clusterRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to get cluster: %w", err)
	}
	return &resourceNetworkInfo{SubnetUrl: getSubnetworkUrl(resourceInfo.Project, resourceInfo.Region, clusterResponse.Subnetwork), NetworkName: clusterResponse.Network, ResourceID: shortenClusterId(clusterResponse.Id)}, nil
}

// Create a GCP cluster with network settings
// Returns the cluster URL and cluster CIDR
func (r *gcpGKE) createWithNetwork(ctx context.Context, cluster *containerpb.CreateClusterRequest, subnetName string, resourceInfo *resourceInfo, firewallsClient *compute.FirewallsClient, additionalAddrSpaces []string) (string, string, error) {
	// Set project and name
	cluster.Parent = fmt.Sprintf("projects/%s/locations/%s", resourceInfo.Project, resourceInfo.Zone)
	cluster.Cluster.Name = resourceInfo.Name

	// Configure network settings to Paraglider VPC and corresponding subnet
	cluster.Cluster.Network = getVpcName(resourceInfo.Namespace)
	cluster.Cluster.Subnetwork = getSubnetworkUrl(resourceInfo.Project, resourceInfo.Region, subnetName)
	controlPlaneCidr := strings.Split(additionalAddrSpaces[0], "/")[0] + "/28" // TODO @smcclure20: Update this once FindUnusedAddressSpaces can give dynamically sized prefixes
	if cluster.Cluster.PrivateClusterConfig == nil {
		cluster.Cluster.PrivateClusterConfig = &containerpb.PrivateClusterConfig{MasterIpv4CidrBlock: controlPlaneCidr}
	} else {
		cluster.Cluster.PrivateClusterConfig.MasterIpv4CidrBlock = controlPlaneCidr
	}
	cluster.Cluster.ClusterIpv4Cidr = additionalAddrSpaces[1]
	cluster.Cluster.ServicesIpv4Cidr = additionalAddrSpaces[2]

	// Create the cluster
	createClusterResp, err := r.client.CreateCluster(ctx, cluster)
	if err != nil {
		return "", "", fmt.Errorf("unable to insert cluster: %w", err)
	}

	// Add network tag which will be used by GCP firewall rules corresponding to Paraglider permit list rules
	// The cluster is fetched again as the Id which is used to create the tag is only available after instance creation
	getClusterRequest := &containerpb.GetClusterRequest{
		Name: fmt.Sprintf(clusterNameFormat, resourceInfo.Project, resourceInfo.Zone, cluster.Cluster.Name),
	}
	getClusterResp, err := r.client.GetCluster(ctx, getClusterRequest)
	if err != nil {
		return "", "", fmt.Errorf("unable to get cluster: %w", err)
	}

	// Add a firewall rule to allow traffic to/from the control plane
	directions := []string{computepb.Firewall_INGRESS.String(), computepb.Firewall_EGRESS.String()}
	for _, direction := range directions {
		insertFirewallReq := &computepb.InsertFirewallRequest{
			Project: resourceInfo.Project,
			FirewallResource: &computepb.Firewall{
				Allowed: []*computepb.Allowed{
					{
						IPProtocol: proto.String("all"),
					},
				},
				Description: proto.String("Paraglider allow cluster egress traffic"),
				Direction:   proto.String(direction),
				Name:        proto.String("paraglider-allow-control-plane-" + strings.ToLower(direction) + "-" + resourceInfo.Name),
				Network:     proto.String(GetVpcUrl(resourceInfo.Project, resourceInfo.Namespace)),
				Priority:    proto.Int32(65500),
				TargetTags:  []string{getClusterNodeTag(resourceInfo.Namespace, getClusterResp.Name, getClusterResp.Id)},
			},
		}
		if direction == computepb.Firewall_EGRESS.String() {
			insertFirewallReq.FirewallResource.DestinationRanges = []string{cluster.Cluster.PrivateClusterConfig.MasterIpv4CidrBlock}
		} else {
			insertFirewallReq.FirewallResource.SourceRanges = []string{cluster.Cluster.PrivateClusterConfig.MasterIpv4CidrBlock}
		}

		insertFirewallOp, err := firewallsClient.Insert(ctx, insertFirewallReq)
		if err != nil {
			return "", "", fmt.Errorf("unable to create firewall rule: %w", err)
		}
		if err = insertFirewallOp.Wait(ctx); err != nil {
			return "", "", fmt.Errorf("unable to wait for the operation: %w", err)
		}
	}

	// Wait for cluster creation to complete before updating with network tags
	for createClusterResp.Status == containerpb.Operation_RUNNING {
		createClusterResp, err = r.client.GetOperation(ctx, &containerpb.GetOperationRequest{Name: fmt.Sprintf("projects/%s/locations/%s/operations/%s", resourceInfo.Project, resourceInfo.Zone, createClusterResp.Name)})
		if err != nil {
			return "", "", fmt.Errorf("unable to get operation: %w", err)
		}
		time.Sleep(5 * time.Second)
	}

	// Update the cluster with network tags
	updateClusterRequest := &containerpb.UpdateClusterRequest{
		Name: fmt.Sprintf(clusterNameFormat, resourceInfo.Project, resourceInfo.Zone, cluster.Cluster.Name),
		Update: &containerpb.ClusterUpdate{
			DesiredNodePoolAutoConfigNetworkTags: &containerpb.NetworkTags{
				Tags: append(getClusterResp.NodePools[0].Config.Tags, getNetworkTag(resourceInfo.Namespace, clusterTypeName, shortenClusterId(getClusterResp.Id))),
			},
		},
	}
	_, err = r.client.UpdateCluster(ctx, updateClusterRequest)
	if err != nil {
		return "", "", fmt.Errorf("unable to set tags: %w", err)
	}

	return getClusterUrl(resourceInfo.Project, resourceInfo.Zone, getClusterResp.Name), getClusterResp.ClusterIpv4Cidr, nil
}

// Parse the resource description and return the cluster request
func (r *gcpGKE) fromResourceDecription(resourceDesc []byte) (*containerpb.CreateClusterRequest, error) {
	createClusterRequest := &containerpb.CreateClusterRequest{}
	err := json.Unmarshal(resourceDesc, createClusterRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource description: %w", err)
	}
	if createClusterRequest.Cluster.Network != "" || createClusterRequest.Cluster.Subnetwork != "" {
		return nil, fmt.Errorf("network settings (subnets and address spaces) should not be specified")
	}
	if createClusterRequest.Cluster.ClusterIpv4Cidr != "" || createClusterRequest.Cluster.ServicesIpv4Cidr != "" {
		return nil, fmt.Errorf("network settings (subnets and address spaces) should not be specified")
	}
	if createClusterRequest.Cluster.PrivateClusterConfig == nil {
		return createClusterRequest, nil
	} else if createClusterRequest.Cluster.PrivateClusterConfig.MasterIpv4CidrBlock != "" {
		return nil, fmt.Errorf("network settings (subnets and address spaces) should not be specified")
	}
	return createClusterRequest, nil
}

// getInstanceUrl returns a fully qualified URL for an instance
func getInstanceUrl(project, zone, instance string) string {
	return computeUrlPrefix + fmt.Sprintf("projects/%s/zones/%s/instances/%s", project, zone, instance)
}

// getClusterUrl returns a fully qualified URL for a cluster
func getClusterUrl(project, zone, cluster string) string {
	return containerUrlPrefix + fmt.Sprintf("projects/%s/locations/%s/clusters/%s", project, zone, cluster)
}
