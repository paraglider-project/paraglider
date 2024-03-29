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
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	container "cloud.google.com/go/container/apiv1"
	containerpb "cloud.google.com/go/container/apiv1/containerpb"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
	"google.golang.org/protobuf/proto"
)

const (
	clusterTypeName   = "cluster"
	instanceTypeName  = "instance"
	clusterNameFormat = "projects/%s/locations/%s/clusters/%s"
)

type ResourceInfo struct {
	Name                       string
	Project                    string
	Zone                       string
	Region                     string
	Namespace                  string
	ResourceType               string
	CreatesOwnSubnet           bool
	NumAdditionalAddressSpaces int
}

type ResourceNetworkInfo struct {
	SubnetURI   string
	ResourceID  string
	NetworkName string
}

func resourceIsInNamespace(network string, namespace string) bool {
	return strings.HasSuffix(network, getVpcName(namespace))
}

// Gets a GCP network tag for a GCP instance
func getNetworkTag(namespace string, resourceType string, resourceId string) string {
	return getInvisinetsNamespacePrefix(namespace) + "-" + resourceType + "-" + resourceId
}

func convertInstanceIdToString(instanceId uint64) string {
	return strconv.FormatUint(instanceId, 16)
}

func shortenClusterId(clusterId string) string {
	return clusterId[:8]
}

func getDefaultClusterTag() string {
	return "invisinets-cluster-default-tag"
}

func getDefaultClusterFirewallRuleName() string {
	return "invisinets-cluster-allow-internet-access"
}

func getClusterNodeTag(clusterName string, clusterId string) string {
	return "gke-" + clusterName + "-" + shortenClusterId(clusterId) + "-node"
}

// Get the firewall rules associated with a resource following the naming convention
func getFirewallRules(ctx context.Context, client *compute.FirewallsClient, project string, resourceID string) ([]*computepb.Firewall, error) {
	firewallRules := []*computepb.Firewall{}
	filter := fmt.Sprintf("name:%s", getFirewallName("", resourceID))
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

// Parse the resource URI and return information about the resource (such as project, zone, name, and type)
func parseResourceUri(resourceUri string) (*ResourceInfo, error) {
	parsedResourceId := parseGCPURL(resourceUri)
	if name, ok := parsedResourceId["instances"]; ok {
		return &ResourceInfo{Project: parsedResourceId["projects"], Zone: parsedResourceId["zones"], Region: getRegionFromZone(parsedResourceId["zones"]), Name: name, ResourceType: instanceTypeName}, nil
	} else if name, ok := parsedResourceId["clusters"]; ok {
		return &ResourceInfo{Project: parsedResourceId["projects"], Zone: parsedResourceId["locations"], Region: getRegionFromZone(parsedResourceId["locations"]), Name: name, ResourceType: clusterTypeName}, nil
	}
	return nil, fmt.Errorf("unable to parse resource URI")
}

// Gets network information about a resource and confirms it is in the correct namespace
// Returns the subnet URI and resource ID (instance ID or cluster ID, not URI since this is used for firewall rule naming)
func GetResourceInfo(ctx context.Context, instancesClient *compute.InstancesClient, clusterClient *container.ClusterManagerClient, resourceInfo *ResourceInfo) (*string, *string, error) {
	if resourceInfo.Namespace == "" {
		return nil, nil, fmt.Errorf("namespace is empty")
	}

	var netInfo *ResourceNetworkInfo
	var err error
	if resourceInfo.ResourceType == instanceTypeName {
		resourceHandler := &GCPInstance{}
		netInfo, err = resourceHandler.GetNetworkInfo(ctx, resourceInfo, instancesClient)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get network info: %w", err)
		}
	} else if resourceInfo.ResourceType == clusterTypeName {
		resourceHandler := &GKE{}
		netInfo, err = resourceHandler.GetNetworkInfo(ctx, resourceInfo, clusterClient)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get network info: %w", err)
		}
		netInfo.ResourceID = shortenClusterId(netInfo.ResourceID)
	} else {
		return nil, nil, fmt.Errorf("unknown resource type")
	}
	if !resourceIsInNamespace(netInfo.NetworkName, resourceInfo.Namespace) {
		return nil, nil, fmt.Errorf("resource is not in namespace")
	}
	return &netInfo.SubnetURI, &netInfo.ResourceID, nil
}

// Determine whether the provided resource description is supported
func IsValidResource(ctx context.Context, resource *invisinetspb.ResourceDescription) (*ResourceInfo, error) {
	insertInstanceRequest := &computepb.InsertInstanceRequest{}
	createClusterRequest := &containerpb.CreateClusterRequest{}
	err := json.Unmarshal(resource.Description, insertInstanceRequest)
	if err == nil && insertInstanceRequest.InstanceResource != nil {
		handler := &GCPInstance{}
		return &ResourceInfo{Project: insertInstanceRequest.Project, Zone: insertInstanceRequest.Zone, Name: *insertInstanceRequest.InstanceResource.Name, NumAdditionalAddressSpaces: handler.GetNumberAddressSpacesRequired()}, nil
	} else if err := json.Unmarshal(resource.Description, createClusterRequest); err == nil {
		project := strings.Split(createClusterRequest.Parent, "/")[1]
		zone := strings.Split(createClusterRequest.Parent, "/")[3]
		handler := &GKE{}
		return &ResourceInfo{Project: project, Zone: zone, Name: createClusterRequest.Cluster.Name, NumAdditionalAddressSpaces: handler.GetNumberAddressSpacesRequired()}, nil
	} else {
		return nil, fmt.Errorf("resource description contains unknown GCP resource")
	}
}

// Read the resource description and provision the resource
func ReadAndProvisionResource(ctx context.Context, resource *invisinetspb.ResourceDescription, subnetName string, resourceInfo *ResourceInfo, instanceClient *compute.InstancesClient, clusterClient *container.ClusterManagerClient, firewallsClient *compute.FirewallsClient, additionalAddrSpaces []string) (string, string, error) {
	insertInstanceRequest := &computepb.InsertInstanceRequest{}
	createClusterRequest := &containerpb.CreateClusterRequest{}
	err := json.Unmarshal(resource.Description, insertInstanceRequest)
	if err == nil && insertInstanceRequest.InstanceResource != nil {
		handler := &GCPInstance{}
		vm, err := handler.FromResourceDecription(resource.Description)
		if err != nil {
			return "", "", err
		}
		return handler.CreateWithNetwork(ctx, vm, subnetName, resourceInfo, instanceClient, firewallsClient)
	} else if err := json.Unmarshal(resource.Description, createClusterRequest); err == nil {
		handler := &GKE{}
		gke, err := handler.FromResourceDecription(resource.Description)
		if err != nil {
			return "", "", err
		}
		return handler.CreateWithNetwork(ctx, gke, subnetName, resourceInfo, clusterClient, firewallsClient, additionalAddrSpaces)
	} else {
		return "", "", fmt.Errorf("resource description contains unknown resource")
	}
}

// Interface for GCP resource which must be implemented for support
type GCPResourceHandler[T any] interface {
	CreateWithNetwork(ctx context.Context, resource *T, subnetName string, resourceInfo *ResourceInfo, client any, firewallsClient *compute.FirewallsClient) (string, string, error)
	FromResourceDecription(resourceDesc []byte) (T, error)
	GetNetworkInfo(ctx context.Context, resourceInfo *ResourceInfo, client any) (*ResourceNetworkInfo, error)
	GetNumberExtraAddressSpacesRequired() int
}

// GCP instance resource handler
type GCPInstance struct {
	GCPResourceHandler[computepb.InsertInstanceRequest]
}

// Get the subnet requirements for a GCP instance
func (r *GCPInstance) GetNumberAddressSpacesRequired() int {
	return 0
}

// Get network information about a GCP instance
// Returns the network name, subnet URI, and instance ID converted to a string for rule naming
func (r *GCPInstance) GetNetworkInfo(ctx context.Context, resourceInfo *ResourceInfo, client *compute.InstancesClient) (*ResourceNetworkInfo, error) {
	instanceRequest := &computepb.GetInstanceRequest{
		Instance: resourceInfo.Name,
		Project:  resourceInfo.Project,
		Zone:     resourceInfo.Zone,
	}
	instanceResponse, err := client.Get(ctx, instanceRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to get instance: %w", err)
	}
	networkName := *instanceResponse.NetworkInterfaces[0].Network
	subnetURI := *instanceResponse.NetworkInterfaces[0].Subnetwork
	resourceID := convertInstanceIdToString(*instanceResponse.Id)
	return &ResourceNetworkInfo{NetworkName: networkName, SubnetURI: subnetURI, ResourceID: resourceID}, nil
}

// Create a GCP instance with network settings
// Returns the instance URI and instance IP
func (r *GCPInstance) CreateWithNetwork(ctx context.Context, instance *computepb.InsertInstanceRequest, subnetName string, resourceInfo *ResourceInfo, client *compute.InstancesClient, firewallsClient *compute.FirewallsClient) (string, string, error) {
	// Configure network settings to Invisinets VPC and corresponding subnet
	instance.InstanceResource.NetworkInterfaces = []*computepb.NetworkInterface{
		{
			Network:    proto.String(GetVpcUri(resourceInfo.Namespace)),
			Subnetwork: proto.String("regions/" + resourceInfo.Region + "/subnetworks/" + subnetName),
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
		Project:  resourceInfo.Project,
		Zone:     resourceInfo.Zone,
	}

	getInstanceResp, err := client.Get(ctx, getInstanceReq)
	if err != nil {
		return "", "", fmt.Errorf("unable to get instance: %w", err)
	}
	setTagsReq := &computepb.SetTagsInstanceRequest{
		Instance: instanceName,
		Project:  resourceInfo.Project,
		Zone:     resourceInfo.Zone,
		TagsResource: &computepb.Tags{
			Items:       append(getInstanceResp.Tags.Items, getNetworkTag(resourceInfo.Namespace, instanceTypeName, convertInstanceIdToString(*instance.InstanceResource.Id))),
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

	return getInstanceUri(resourceInfo.Project, resourceInfo.Zone, instanceName), *getInstanceResp.NetworkInterfaces[0].NetworkIP, nil
}

// Parse the resource description and return the instance request
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

// GCP cluster resource handler
type GKE struct {
	GCPResourceHandler[containerpb.CreateClusterRequest]
}

// Get the subnet requirements for a GCP instance
func (r *GKE) GetNumberAddressSpacesRequired() int {
	return 3
}

// Get network information about a GCP cluster
// Returns the subnet URI and resource ID (cluster ID, not URI since this is used for firewall rule naming)
func (r *GKE) GetNetworkInfo(ctx context.Context, resourceInfo *ResourceInfo, client *container.ClusterManagerClient) (*ResourceNetworkInfo, error) {
	clusterRequest := &containerpb.GetClusterRequest{
		Name: fmt.Sprintf(clusterNameFormat, resourceInfo.Project, resourceInfo.Zone, resourceInfo.Name),
	}
	clusterResponse, err := client.GetCluster(ctx, clusterRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to get cluster: %w", err)
	}
	return &ResourceNetworkInfo{SubnetURI: getSubnetworkURL(resourceInfo.Project, resourceInfo.Region, clusterResponse.Subnetwork), NetworkName: clusterResponse.Network, ResourceID: clusterResponse.Id}, nil
}

// Create a GCP cluster with network settings
// Returns the cluster URI and cluster CIDR
func (r *GKE) CreateWithNetwork(ctx context.Context, cluster *containerpb.CreateClusterRequest, subnetName string, resourceInfo *ResourceInfo, client *container.ClusterManagerClient, firewallsClient *compute.FirewallsClient, additionalAddrSpaces []string) (string, string, error) {
	// Configure network settings to Invisinets VPC and corresponding subnet
	cluster.Cluster.Network = getVpcName(resourceInfo.Namespace)
	cluster.Cluster.Subnetwork = getSubnetworkURL(resourceInfo.Project, resourceInfo.Region, subnetName)
	controlPlaneCidr := strings.Split(additionalAddrSpaces[0], "/")[0] + "/28" // TODO @smcclure20: Update this once FindUnusedAddressSpaces can give dynamically sized prefixes
	if cluster.Cluster.PrivateClusterConfig == nil {
		cluster.Cluster.PrivateClusterConfig = &containerpb.PrivateClusterConfig{MasterIpv4CidrBlock: controlPlaneCidr}
	} else {
		cluster.Cluster.PrivateClusterConfig.MasterIpv4CidrBlock = controlPlaneCidr
	}
	cluster.Cluster.ClusterIpv4Cidr = additionalAddrSpaces[1]
	cluster.Cluster.ServicesIpv4Cidr = additionalAddrSpaces[2]

	// Create the cluster
	createClusterResp, err := client.CreateCluster(ctx, cluster)
	if err != nil {
		return "", "", fmt.Errorf("unable to insert cluster: %w", err)
	}

	// Add network tag which will be used by GCP firewall rules corresponding to Invisinets permit list rules
	// The cluster is fetched again as the Id which is used to create the tag is only available after instance creation
	getClusterRequest := &containerpb.GetClusterRequest{
		Name: fmt.Sprintf(clusterNameFormat, resourceInfo.Project, resourceInfo.Zone, cluster.Cluster.Name),
	}
	getClusterResp, err := client.GetCluster(ctx, getClusterRequest)
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
				Description: proto.String("Invisinets allow cluster egress traffic"),
				Direction:   proto.String(direction),
				Name:        proto.String("invisinets-allow-control-plane-" + strings.ToLower(direction) + "-" + resourceInfo.Name),
				Network:     proto.String(GetVpcUri(resourceInfo.Namespace)),
				Priority:    proto.Int32(65500),
				TargetTags:  []string{getClusterNodeTag(getClusterResp.Name, getClusterResp.Id)},
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
		createClusterResp, err = client.GetOperation(ctx, &containerpb.GetOperationRequest{Name: fmt.Sprintf("projects/%s/locations/%s/operations/%s", resourceInfo.Project, resourceInfo.Zone, createClusterResp.Name)})
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
	_, err = client.UpdateCluster(ctx, updateClusterRequest)
	if err != nil {
		return "", "", fmt.Errorf("unable to set tags: %w", err)
	}

	return getClusterUri(resourceInfo.Project, resourceInfo.Zone, getClusterResp.Name), getClusterResp.ClusterIpv4Cidr, nil
}

// Parse the resource description and return the cluster request
func (r *GKE) FromResourceDecription(resourceDesc []byte) (*containerpb.CreateClusterRequest, error) {
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
