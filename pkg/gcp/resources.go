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
	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
	"google.golang.org/protobuf/proto"
)

const (
	clusterTypeName               = "cluster"
	instanceTypeName              = "instance"
	privateServiceConnectTypeName = "privateServiceConnect"
	clusterNameFormat             = "projects/%s/locations/%s/clusters/%s"
	addressType                   = "INTERNAL"
	addressPurpose                = "PRIVATE_SERVICE_CONNECT"
	paragliderLabel               = "paraglider_ns"
	globalRegion                  = "global"
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
	Address     string
}

type ServiceAttachmentDescription struct {
	Url    string `json:"url"`
	Bundle string `json:"bundle"`
}

func resourceIsInNamespace(network string, namespace string) bool {
	return strings.HasSuffix(network, getVpcName(namespace))
}

// Gets a network tag for a resource
func getNetworkTag(namespace string, resourceType string, resourceId string) string {
	return getParagliderNamespacePrefix(namespace) + "-" + resourceType + "-" + resourceId
}

// Get name for an IP address resource
func getAddressName(resourceName string) string {
	return paragliderPrefix + "-" + resourceName + "-address"
}

// Convert integer resource IDs to a string for naming
func convertIntIdToString(id uint64) string {
	stringId := strconv.FormatUint(id, 16)
	if len(stringId) > 8 {
		return stringId[:8]
	}
	return stringId
}

// Shorten cluster IDs for use in associated resource names
func shortenClusterId(clusterId string) string {
	return clusterId[:8]
}

// Get a network tag for a cluster
func getClusterNodeTag(namespace string, clusterName string, clusterId string) string {
	return getParagliderNamespacePrefix(namespace) + "-gke-" + clusterName + "-" + shortenClusterId(clusterId) + "-node"
}

// getInstanceUrl returns a fully qualified URL for an instance
func getInstanceUrl(project, zone, instance string) string {
	return computeUrlPrefix + fmt.Sprintf("projects/%s/zones/%s/instances/%s", project, zone, instance)
}

// getClusterUrl returns a fully qualified URL for a cluster
func getClusterUrl(project, zone, cluster string) string {
	return containerUrlPrefix + fmt.Sprintf("projects/%s/locations/%s/clusters/%s", project, zone, cluster)
}

// Get the firewall rules associated with a resource following the naming convention
func getFirewallRules(ctx context.Context, project string, resourceID string, clients *GCPClients) ([]*computepb.Firewall, error) {
	client, err := clients.GetOrCreateFirewallsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get firewalls client: %w", err)
	}

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
	} else if name, ok := parsedResourceId["forwardingRules"]; ok {
		return &resourceInfo{Project: parsedResourceId["projects"], Region: parsedResourceId["regions"], Name: name, ResourceType: privateServiceConnectTypeName}, nil
	}
	return nil, fmt.Errorf("unable to parse resource URL")
}

// Get the resource handler for a given resource type with necessary clients initialized if provided
func getResourceHandler(ctx context.Context, resourceType string, clients *GCPClients) (GCPResourceHandler, error) {
	var handler GCPResourceHandler
	if resourceType == instanceTypeName {
		handler = &instanceHandler{}
	} else if resourceType == clusterTypeName {
		handler = &clusterHandler{}
	} else if resourceType == privateServiceConnectTypeName {
		handler = &privateServiceHandler{}
	} else {
		return nil, fmt.Errorf("unknown resource type")
	}
	if clients != nil {
		err := handler.initClients(ctx, clients)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize clients: %w", err)
		}
	}
	return handler, nil
}

// Get the resource handler for a given resource description
// The handler will not have clients initialized
func getResourceHandlerFromDescription(resourceDesc []byte) (GCPResourceHandler, error) {
	insertInstanceRequest := &computepb.InsertInstanceRequest{}
	createClusterRequest := &containerpb.CreateClusterRequest{}
	serviceAttachment := &ServiceAttachmentDescription{}
	err := json.Unmarshal(resourceDesc, insertInstanceRequest)
	if err == nil && insertInstanceRequest.InstanceResource != nil {
		return &instanceHandler{}, nil
	} else if err := json.Unmarshal(resourceDesc, createClusterRequest); err == nil && createClusterRequest.Cluster != nil {
		return &clusterHandler{}, nil
	} else if err := json.Unmarshal(resourceDesc, serviceAttachment); err == nil {
		return &privateServiceHandler{}, nil
	} else {
		return nil, fmt.Errorf("resource description contains unknown GCP resource")
	}
}

// Gets network information about a resource and confirms it is in the correct namespace
// Returns the subnet URL and resource ID (instance ID or cluster ID, not URL since this is used for firewall rule naming)
func GetResourceNetworkInfo(ctx context.Context, resourceInfo *resourceInfo, clients *GCPClients) (*resourceNetworkInfo, error) {
	if resourceInfo.Namespace == "" {
		return nil, fmt.Errorf("namespace is empty")
	}

	handler, err := getResourceHandler(ctx, resourceInfo.ResourceType, clients)
	if err != nil {
		return nil, fmt.Errorf("unable to get resource handler: %w", err)
	}
	netInfo, err := handler.getNetworkInfo(ctx, resourceInfo)
	if err != nil {
		return nil, fmt.Errorf("unable to get network info: %w", err)
	}

	if !resourceIsInNamespace(netInfo.NetworkName, resourceInfo.Namespace) {
		return nil, fmt.Errorf("resource is not in namespace")
	}
	return netInfo, nil
}

// // Verifies the existence of a GCP resource described in an AttachResourceRequest and returns the resourceInfo
// func (r *instanceHandler) IsValidResource(ctx context.Context, req *paragliderpb.AttachResourceRequest) (*resourceInfo, error) {
// 	// Parse the resource URL to get the resourceInfo (project, zone, name, etc)
// 	resourceInfo, err := parseResourceUrl(req.GetResource())
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse resource URL: %w", err)
// 	}

// 	// Make a GetInstanceRequest to verify the instance exists
// 	instanceRequest := &computepb.GetInstanceRequest{
// 		Instance: resourceInfo.Name,
// 		Project:  resourceInfo.Project,
// 		Zone:     resourceInfo.Zone,
// 	}
// 	_, err = r.client.Get(ctx, instanceRequest)
// 	if err != nil {
// 		return nil, fmt.Errorf("unable to get instance: %w", err)
// 	}

// 	resourceInfo.Namespace = req.GetNamespace()

// 	return resourceInfo, nil
// }

// Read parameters from within the resource description and ensure it is a valid resource
func IsValidResource(ctx context.Context, resource *paragliderpb.CreateResourceRequest) (*resourceInfo, error) {
	// Verify resource is supported
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
func ReadAndProvisionResource(ctx context.Context, resource *paragliderpb.CreateResourceRequest, subnetName string, resourceInfo *resourceInfo, additionalAddrSpaces []string, clients *GCPClients) (string, string, error) {
	handler, err := getResourceHandler(ctx, resourceInfo.ResourceType, clients)
	if err != nil {
		return "", "", fmt.Errorf("unable to get resource handler: %w", err)
	}
	return handler.readAndProvisionResource(ctx, resource, subnetName, resourceInfo, additionalAddrSpaces)
}

// Get the type and value of the firewall target for a resource
func GetFirewallTarget(ctx context.Context, resourceInfo *resourceInfo, netInfo *resourceNetworkInfo) (*firewallTarget, error) {
	handler, err := getResourceHandler(ctx, resourceInfo.ResourceType, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to get resource handler: %w", err)
	}
	target := handler.getFirewallTarget(resourceInfo, netInfo)
	return &target, nil
}

// Returns the resource and network info if the resource complies with paraglider requirements. Otherwise, it returns an error
func (r *instanceHandler) ValidateResourceCompliesWithParagliderRequirements(ctx context.Context, resourceReq *paragliderpb.AttachResourceRequest, project string, resourceID string, clients *GCPClients) (*resourceInfo, *resourceNetworkInfo, error) {
	// Get the ResourceInfo from AttachResourceRequest
	resourceInfo, err := parseResourceUrl(resourceReq.GetResource())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse resource URL: %w", err)
	}

	resourceInfo.Namespace = resourceReq.GetNamespace()

	networkInfo, err := GetResourceNetworkInfo(ctx, resourceInfo, clients)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in getting resource %s network info: %w", resourceID, err)
	}

	// Returns the network name, subnet URL, IP, and instance ID converted to a string for rule naming
	instanceRequest := &computepb.GetInstanceRequest{
		Instance: resourceInfo.Name,
		Project:  resourceInfo.Project,
		Zone:     resourceInfo.Zone,
	}
	instanceResponse, err := r.client.Get(ctx, instanceRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get instance: %w", err)
	}

	// Ensure the Vnet address space doesn't overlap with paraglider's address space
	vpcName := *instanceResponse.NetworkInterfaces[0].Network
	isOverlapping, err := DoesVPCOverlapWithParaglider(ctx, resourceInfo, vpcName, clients)
	if err != nil {
		return nil, nil, fmt.Errorf("error checking if VPC overlaps with Paraglider: %w", err)
	}

	if isOverlapping {
		return nil, nil, fmt.Errorf("Resource %s Network Address Space overlaps with Paraglider Network Address Space. Not allowed", resourceID)
	}

	// Fetch firewall rules for the resource using getFirewallRules function
	firewallRules, err := getFirewallRules(ctx, project, resourceID, clients)
	if err != nil {
		return nil, nil, fmt.Errorf("Error retrieving firewall rules for resource %s: %w", resourceID, err)
	}

	// Call CheckFirewallRulesCompliance to verify firewall rule compliance
	isCompliant, err := CheckFirewallRulesCompliance(firewallRules)
	if err != nil || !isCompliant {
		return nil, nil, fmt.Errorf("Firewall rules are not compliant: %w", err)
	}
	
	return resourceInfo, networkInfo, nil
}

// GetVPCAddressSpace retrieves the address space for a given VPC network
func GetVPCAddressSpace(ctx context.Context, project, vpcName string, clients *GCPClients) ([]string, error) {
	networksClient, err := clients.GetOrCreateNetworksClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get networks client: %w", err)
	}
	subnetworksClient, err := clients.GetOrCreateSubnetworksClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get subnetworks client: %w", err)
	}

	getNetworkReq := &computepb.GetNetworkRequest{
		Network: vpcName,
		Project: project,
	}

	getNetworkResp, err := networksClient.Get(ctx, getNetworkReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get paraglider vpc network: %w", err)
	}

	var addressSpaces []string

	// Iterate over all subnetworks associated with the VPC
	for _, subnetURL := range getNetworkResp.Subnetworks {
		// Parse the subnetwork URL to get region and subnetwork name
		parsedSubnetURL := parseUrl(subnetURL)

		// Prepare request to get subnetwork details
		getSubnetworkRequest := &computepb.GetSubnetworkRequest{
			Project:    project,
			Region:     parsedSubnetURL["regions"],
			Subnetwork: parsedSubnetURL["subnetworks"],
		}

		// Fetch subnetwork details
		getSubnetworkResp, err := subnetworksClient.Get(ctx, getSubnetworkRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to get subnetwork: %w", err)
		}

		// Append the primary CIDR range
		addressSpaces = append(addressSpaces, *getSubnetworkResp.IpCidrRange)

		// Append the secondary CIDR ranges (if any)
		for _, secondaryRange := range getSubnetworkResp.SecondaryIpRanges {
			addressSpaces = append(addressSpaces, *secondaryRange.IpCidrRange)
		}
	}

	// Return the list of address spaces (CIDR ranges)
	return addressSpaces, nil
}

// DoesVnetOverlapWithParaglider checks if the GCP VPC's address space overlaps with any of the used address spaces
func DoesVPCOverlapWithParaglider(ctx context.Context, resourceInfo *resourceInfo, vpcName string, clients *GCPClients) (bool, error) {
	// Get VPC address space (CIDR block)
	// vpcAddressSpaces, err := GetVPCAddressSpace(ctx, resourceInfo.Project, vpcName, clients)
	// if err != nil {
	// 	return false, fmt.Errorf("failed to get VPC address space: %v", err)
	// }

	// GetUsedAddressSpaces by checking the subnetworks IpCidrRange
	// PASS IN OR INITIALIZE CLIENTS?
	// clients := &GCPClients{}
	networksClient, err := clients.GetOrCreateNetworksClient(ctx)
	if err != nil {
		return false, fmt.Errorf("unable to get networks client: %w", err)
	}
	subnetworksClient, err := clients.GetOrCreateSubnetworksClient(ctx)
	if err != nil {
		return false, fmt.Errorf("unable to get subnetworks client: %w", err)
	}

	// getNetworkReq := &computepb.GetNetworkRequest{
	// 	Network: vpcName,
	// 	Project: resourceInfo.Project,
	// }

	// getNetworkResp, err := networksClient.Get(ctx, getNetworkReq)
	// if err != nil {
	// 	return false, fmt.Errorf("failed to get paraglider vpc network: %w", err)
	// }

	req := &paragliderpb.GetUsedAddressSpacesRequest{
		Deployments: []*paragliderpb.ParagliderDeployment{
			{Id: "projects/" + resourceInfo.Project, Namespace: resourceInfo.Namespace},
		},
	}

	resp := &paragliderpb.GetUsedAddressSpacesResponse{}
	resp.AddressSpaceMappings = make([]*paragliderpb.AddressSpaceMapping, len(req.Deployments))
	for i, deployment := range req.Deployments {
		resp.AddressSpaceMappings[i] = &paragliderpb.AddressSpaceMapping{
			Cloud:     utils.GCP,
			Namespace: deployment.Namespace,
		}
		project := parseUrl(deployment.Id)["projects"]

		vpcName := getVpcName(deployment.Namespace)
		getNetworkReq := &computepb.GetNetworkRequest{
			Network: vpcName,
			Project: project,
		}

		getNetworkResp, err := networksClient.Get(ctx, getNetworkReq)
		if err != nil {
			if isErrorNotFound(err) {
				continue
			} else {
				return false, fmt.Errorf("failed to get paraglider vpc network: %w", err)
			}
		}
		resp.AddressSpaceMappings[i].AddressSpaces = []string{}
		for _, subnetURL := range getNetworkResp.Subnetworks {
			parsedSubnetURL := parseUrl(subnetURL)
			getSubnetworkRequest := &computepb.GetSubnetworkRequest{
				Project:    project,
				Region:     parsedSubnetURL["regions"],
				Subnetwork: parsedSubnetURL["subnetworks"],
			}
			getSubnetworkResp, err := subnetworksClient.Get(ctx, getSubnetworkRequest)
			if err != nil {
				return false, fmt.Errorf("failed to get paraglider subnetwork: %w", err)
			}

			resp.AddressSpaceMappings[i].AddressSpaces = append(resp.AddressSpaceMappings[i].AddressSpaces, *getSubnetworkResp.IpCidrRange)
			for _, secondaryRange := range getSubnetworkResp.SecondaryIpRanges {
				resp.AddressSpaceMappings[i].AddressSpaces = append(resp.AddressSpaceMappings[i].AddressSpaces, *secondaryRange.IpCidrRange)
			}
		}
	}

	return false, nil
}

// Interface to implement to support a resource
type GCPResourceHandler interface {
	// Read and provision the resource with the provided subnet
	readAndProvisionResource(ctx context.Context, resource *paragliderpb.CreateResourceRequest, subnetName string, resourceInfo *resourceInfo, additionalAddrSpaces []string) (string, string, error)
	// Get network information about the resource
	getNetworkInfo(ctx context.Context, resourceInfo *resourceInfo) (*resourceNetworkInfo, error)
	// Get information about the resource from the resource description
	getResourceInfo(ctx context.Context, resource *paragliderpb.CreateResourceRequest) (*resourceInfo, error)
	// Initialize necessary clients
	initClients(ctx context.Context, clients *GCPClients) error
	// Get target for firewall rules
	getFirewallTarget(resourceInfo *resourceInfo, netInfo *resourceNetworkInfo) firewallTarget
}

// GCP instance resource handler
type instanceHandler struct {
	GCPResourceHandler
	client *compute.InstancesClient
}

// Initialize necessary clients for the handler
func (r *instanceHandler) initClients(ctx context.Context, clients *GCPClients) error {
	client, err := clients.GetOrCreateInstancesClient(ctx)
	if err != nil {
		return err
	}
	r.client = client
	return nil
}

// Get the resource information for an instance
func (r *instanceHandler) getResourceInfo(ctx context.Context, resource *paragliderpb.CreateResourceRequest) (*resourceInfo, error) {
	insertInstanceRequest := &computepb.InsertInstanceRequest{}
	err := json.Unmarshal(resource.Description, insertInstanceRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource description: %w", err)
	}
	region := getRegionFromZone(insertInstanceRequest.Zone)
	return &resourceInfo{Name: resource.Name, Region: region, Zone: insertInstanceRequest.Zone, NumAdditionalAddressSpaces: r.getNumberAddressSpacesRequired(), ResourceType: instanceTypeName}, nil
}

// Read and provision an instance
func (r *instanceHandler) readAndProvisionResource(ctx context.Context, resource *paragliderpb.CreateResourceRequest, subnetName string, resourceInfo *resourceInfo, additionalAddrSpaces []string) (string, string, error) {
	vm, err := r.fromResourceDecription(resource.Description)
	if err != nil {
		return "", "", err
	}
	return r.createWithNetwork(ctx, vm, subnetName, resourceInfo)
}

// Get the subnet requirements for an instance
func (r *instanceHandler) getNumberAddressSpacesRequired() int {
	return 0
}

// Get the firewall target type and value for a specific instance
func (r *instanceHandler) getFirewallTarget(resourceInfo *resourceInfo, netInfo *resourceNetworkInfo) firewallTarget {
	return firewallTarget{TargetType: targetTypeTag, Target: getNetworkTag(resourceInfo.Namespace, instanceTypeName, netInfo.ResourceID)}
}

// Get network information about an instance
// Returns the network name, subnet URL, IP, and instance ID converted to a string for rule naming
func (r *instanceHandler) getNetworkInfo(ctx context.Context, resourceInfo *resourceInfo) (*resourceNetworkInfo, error) {
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
	resourceID := convertIntIdToString(*instanceResponse.Id)
	ip := *instanceResponse.NetworkInterfaces[0].NetworkIP
	return &resourceNetworkInfo{NetworkName: networkName, SubnetUrl: subnetUrl, ResourceID: resourceID, Address: ip}, nil
}

// // Get the resource information for an instance from an AttachResourceRequest
// func (r *instanceHandler) getResourceInfo(ctx context.Context, req *paragliderpb.AttachResourceRequest) (*resourceInfo, error) {
// 	resourceID := req.GetResource()

// 	// Retrieve resource ID info (this could be from a database, GCP API, etc.)
// 	resourceIDInfo, err := getResourceIDInfo(resourceID)
// 	if err != nil {
// 		return nil, fmt.Errorf("unable to get resource ID info: %w", err)
// 	}

// 	// Construct the resource info based on the retrieved data
// 	region := getRegionFromZone(resourceIDInfo.Zone)
// 	return &resourceInfo{
// 		Name:         resourceIDInfo.Name,
// 		Project:      resourceIDInfo.Project,
// 		Zone:         resourceIDInfo.Zone,
// 		Region:       region,
// 		ResourceType: instanceTypeName,
// 	}, nil
// }

// Create an instance with given network settings
// Returns the instance URL and instance IP
func (r *instanceHandler) createWithNetwork(ctx context.Context, instance *computepb.InsertInstanceRequest, subnetName string, resourceInfo *resourceInfo) (string, string, error) {
	// Set project and name
	instance.Project = resourceInfo.Project
	instance.InstanceResource.Name = proto.String(resourceInfo.Name)

	// Configure network settings to Paraglider VPC and corresponding subnet
	instance.InstanceResource.NetworkInterfaces = []*computepb.NetworkInterface{
		{
			Network:    proto.String(getVpcUrl(resourceInfo.Project, resourceInfo.Namespace)),
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
			Items:       append(existingTags, getNetworkTag(resourceInfo.Namespace, instanceTypeName, convertIntIdToString(*getInstanceResp.Id))),
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
func (r *instanceHandler) fromResourceDecription(resourceDesc []byte) (*computepb.InsertInstanceRequest, error) {
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
type clusterHandler struct {
	GCPResourceHandler
	client          *container.ClusterManagerClient
	firewallsClient *compute.FirewallsClient
}

// Initialize necessary clients for the handler
func (r *clusterHandler) initClients(ctx context.Context, clients *GCPClients) error {
	client, err := clients.GetOrCreateClustersClient(ctx)
	if err != nil {
		return err
	}
	r.client = client

	firewallsClient, err := clients.GetOrCreateFirewallsClient(ctx)
	if err != nil {
		return err
	}
	r.firewallsClient = firewallsClient

	return nil
}

// Read and provision a cluster
func (r *clusterHandler) readAndProvisionResource(ctx context.Context, resource *paragliderpb.CreateResourceRequest, subnetName string, resourceInfo *resourceInfo, additionalAddrSpaces []string) (string, string, error) {
	gke, err := r.fromResourceDecription(resource.Description)
	if err != nil {
		return "", "", err
	}
	return r.createWithNetwork(ctx, gke, subnetName, resourceInfo, additionalAddrSpaces)
}

// Get the resource information for a cluster
func (r *clusterHandler) getResourceInfo(ctx context.Context, resource *paragliderpb.CreateResourceRequest) (*resourceInfo, error) {
	createClusterRequest := &containerpb.CreateClusterRequest{}
	err := json.Unmarshal(resource.Description, createClusterRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource description: %w", err)
	}
	zone := strings.Split(createClusterRequest.Parent, "/")[3]
	region := getRegionFromZone(zone)
	return &resourceInfo{Name: resource.Name, Region: region, Zone: zone, NumAdditionalAddressSpaces: r.getNumberAddressSpacesRequired(), ResourceType: clusterTypeName}, nil
}

// Get the subnet requirements for a cluster
func (r *clusterHandler) getNumberAddressSpacesRequired() int {
	return 3
}

// Get the firewall target type and value for a specific cluster
func (r *clusterHandler) getFirewallTarget(resourceInfo *resourceInfo, netInfo *resourceNetworkInfo) firewallTarget {
	return firewallTarget{TargetType: targetTypeTag, Target: getNetworkTag(resourceInfo.Namespace, clusterTypeName, netInfo.ResourceID)}
}

// Get network information about a cluster
// Returns the network name, subnet URL, and resource ID (cluster ID, not URL since this is used for firewall rule naming)
func (r *clusterHandler) getNetworkInfo(ctx context.Context, resourceInfo *resourceInfo) (*resourceNetworkInfo, error) {
	clusterRequest := &containerpb.GetClusterRequest{
		Name: fmt.Sprintf(clusterNameFormat, resourceInfo.Project, resourceInfo.Zone, resourceInfo.Name),
	}
	clusterResponse, err := r.client.GetCluster(ctx, clusterRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to get cluster: %w", err)
	}
	return &resourceNetworkInfo{SubnetUrl: getSubnetworkUrl(resourceInfo.Project, resourceInfo.Region, clusterResponse.Subnetwork), NetworkName: clusterResponse.Network, ResourceID: shortenClusterId(clusterResponse.Id)}, nil
}

// Create a cluster with given network settings
// Returns the cluster URL and cluster CIDR
func (r *clusterHandler) createWithNetwork(ctx context.Context, cluster *containerpb.CreateClusterRequest, subnetName string, resourceInfo *resourceInfo, additionalAddrSpaces []string) (string, string, error) {
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
				Network:     proto.String(getVpcUrl(resourceInfo.Project, resourceInfo.Namespace)),
				Priority:    proto.Int32(65500),
				TargetTags:  []string{getClusterNodeTag(resourceInfo.Namespace, getClusterResp.Name, getClusterResp.Id)},
			},
		}
		if direction == computepb.Firewall_EGRESS.String() {
			insertFirewallReq.FirewallResource.DestinationRanges = []string{cluster.Cluster.PrivateClusterConfig.MasterIpv4CidrBlock}
		} else {
			insertFirewallReq.FirewallResource.SourceRanges = []string{cluster.Cluster.PrivateClusterConfig.MasterIpv4CidrBlock}
		}

		insertFirewallOp, err := r.firewallsClient.Insert(ctx, insertFirewallReq)
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
func (r *clusterHandler) fromResourceDecription(resourceDesc []byte) (*containerpb.CreateClusterRequest, error) {
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

// GCP private service connect
type privateServiceHandler struct {
	GCPResourceHandler
	addressesClient        *compute.AddressesClient
	globalAddressesClient  *compute.GlobalAddressesClient
	forwardingClient       *compute.ForwardingRulesClient
	globalForwardingClient *compute.GlobalForwardingRulesClient
	attachmentsClient      *compute.ServiceAttachmentsClient
}

// Initialize necessary clients for the handler
func (r *privateServiceHandler) initClients(ctx context.Context, clients *GCPClients) error {
	addressesClient, err := clients.GetOrCreateAddressesClient(ctx)
	if err != nil {
		return err
	}
	r.addressesClient = addressesClient

	globalAddressesClient, err := clients.GetOrCreateGlobalAddressesClient(ctx)
	if err != nil {
		return err
	}
	r.globalAddressesClient = globalAddressesClient

	forwardingClient, err := clients.GetOrCreateForwardingClient(ctx)
	if err != nil {
		return err
	}
	r.forwardingClient = forwardingClient

	globalForwardingClient, err := clients.GetOrCreateGlobalForwardingClient(ctx)
	if err != nil {
		return err
	}
	r.globalForwardingClient = globalForwardingClient

	attachmentsClient, err := clients.GetOrCreateServiceAttachmentsClient(ctx)
	if err != nil {
		return err
	}
	r.attachmentsClient = attachmentsClient

	return nil
}

// Read and provision a private service connect endpoint to associate with a service attachment
func (r *privateServiceHandler) readAndProvisionResource(ctx context.Context, resource *paragliderpb.CreateResourceRequest, subnetName string, resourceInfo *resourceInfo, additionalAddrSpaces []string) (string, string, error) {
	description := &ServiceAttachmentDescription{}
	err := json.Unmarshal(resource.Description, description)
	if err != nil {
		return "", "", fmt.Errorf("unable to parse resource description: %w", err)
	}
	return r.createWithNetwork(ctx, *description, subnetName, resourceInfo, additionalAddrSpaces[0])
}

// Get the resource information about a service attachment
func (r *privateServiceHandler) getResourceInfo(ctx context.Context, resource *paragliderpb.CreateResourceRequest) (*resourceInfo, error) {
	description := &ServiceAttachmentDescription{}
	err := json.Unmarshal(resource.Description, description)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource description: %w", err)
	}
	var region string
	if description.Url != "" {
		urlParams := parseUrl(description.Url)
		if _, ok := urlParams["serviceAttachments"]; !ok {
			return nil, fmt.Errorf("invalid service attachment URL")
		}
		if _, ok := urlParams["regions"]; !ok {
			return nil, fmt.Errorf("invalid service attachment URL")
		}
		region = urlParams["regions"]
	} else {
		region = globalRegion
	}

	return &resourceInfo{Region: region, NumAdditionalAddressSpaces: r.getNumberAddressSpacesRequired(description), ResourceType: privateServiceConnectTypeName, Name: resource.Name}, nil
}

// Get the subnet requirements for a private service connect attachment
func (r *privateServiceHandler) getNumberAddressSpacesRequired(description *ServiceAttachmentDescription) int {
	if description.Bundle != "" {
		return 1
	}

	return 0
}

// Get the firewall target type and value for a specific service attachment
func (r *privateServiceHandler) getFirewallTarget(resourceInfo *resourceInfo, netInfo *resourceNetworkInfo) firewallTarget {
	return firewallTarget{TargetType: targetTypeAddress, Target: netInfo.Address}
}

// Get network information about a service attachment
// Returns the network name, resource ID (service attachment ID, not URL since this is used for firewall rule naming), and IP address
func (r *privateServiceHandler) getNetworkInfo(ctx context.Context, resourceInfo *resourceInfo) (*resourceNetworkInfo, error) {
	var ruleId string
	var address string
	if resourceInfo.Region != globalRegion {
		// Get the forwarding rule
		forwardingRule, err := r.forwardingClient.Get(ctx, &computepb.GetForwardingRuleRequest{
			Project:        resourceInfo.Project,
			Region:         resourceInfo.Region,
			ForwardingRule: resourceInfo.Name,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to get forwarding rule: %w", err)
		}
		ruleId = convertIntIdToString(*forwardingRule.Id)

		// Get the address information
		addressRequest := &computepb.GetAddressRequest{
			Address: getAddressName(resourceInfo.Name),
			Project: resourceInfo.Project,
			Region:  resourceInfo.Region,
		}
		addr, err := r.addressesClient.Get(ctx, addressRequest)
		if err != nil {
			return nil, fmt.Errorf("unable to get address: %w", err)
		}
		address = *addr.Address
	} else {
		// Get the forwarding rule
		forwardingRule, err := r.globalForwardingClient.Get(ctx, &computepb.GetGlobalForwardingRuleRequest{
			Project:        resourceInfo.Project,
			ForwardingRule: resourceInfo.Name,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to get forwarding rule: %w", err)
		}
		ruleId = convertIntIdToString(*forwardingRule.Id)

		// Get the address information
		addressRequest := &computepb.GetGlobalAddressRequest{
			Address: getAddressName(resourceInfo.Name),
			Project: resourceInfo.Project,
		}
		addr, err := r.globalAddressesClient.Get(ctx, addressRequest)
		if err != nil {
			return nil, fmt.Errorf("unable to get address: %w", err)
		}
		address = *addr.Address
	}

	return &resourceNetworkInfo{NetworkName: getVpcName(resourceInfo.Namespace), ResourceID: ruleId, Address: address}, nil
}

// Create a private service connect endpoint with given network settings
func (r *privateServiceHandler) createWithNetwork(ctx context.Context, service ServiceAttachmentDescription, subnetName string, resourceInfo *resourceInfo, additionalAddress string) (string, string, error) {
	// Reserve an IP address to be the endpoint
	addressName := getAddressName(resourceInfo.Name)
	addressResource := &computepb.Address{
		Name:        &addressName,
		Labels:      map[string]string{paragliderLabel: resourceInfo.Namespace},
		AddressType: proto.String(addressType),
	}

	// For GCP services, the address must be outside the range of the VPC
	var addressURL string
	var address string
	var ruleURI string
	if service.Url != "" {
		addrRequest := computepb.InsertAddressRequest{
			Project:         resourceInfo.Project,
			Region:          resourceInfo.Region,
			AddressResource: addressResource,
		}
		addrRequest.AddressResource.Subnetwork = proto.String(getSubnetworkUrl(resourceInfo.Project, resourceInfo.Region, subnetName))

		addrOp, err := r.addressesClient.Insert(ctx, &addrRequest)
		if err != nil {
			return "", "", fmt.Errorf("unable to insert address: %w", err)
		}
		if err = addrOp.Wait(ctx); err != nil {
			return "", "", fmt.Errorf("unable to wait for the operation: %w", err)
		}

		// Get the allocated address
		getAddressReq := computepb.GetAddressRequest{
			Project: resourceInfo.Project,
			Region:  resourceInfo.Region,
			Address: addressName,
		}
		addr, err := r.addressesClient.Get(ctx, &getAddressReq)
		if err != nil {
			return "", "", fmt.Errorf("unable to get address: %w", err)
		}
		addressURL = *addr.SelfLink
		address = *addr.Address

		// Create a forwarding rule for the endpoint
		forwardingRuleRequest := computepb.InsertForwardingRuleRequest{
			Project: resourceInfo.Project,
			Region:  resourceInfo.Region,
			ForwardingRuleResource: &computepb.ForwardingRule{
				Name:                 proto.String(resourceInfo.Name),
				IPAddress:            proto.String(addressURL),
				Network:              proto.String(getVpcUrl(resourceInfo.Project, resourceInfo.Namespace)),
				Target:               proto.String(service.Url),
				AllowPscGlobalAccess: proto.Bool(true),
			},
		}

		forwardingRuleOp, err := r.forwardingClient.Insert(ctx, &forwardingRuleRequest)
		if err != nil {
			return "", "", fmt.Errorf("unable to insert forwarding rule: %w", err)
		}
		if err = forwardingRuleOp.Wait(ctx); err != nil {
			return "", "", fmt.Errorf("unable to wait for the operation: %w", err)
		}

		// Get the URI of the forwarding rule created
		forwardingRule, err := r.forwardingClient.Get(ctx, &computepb.GetForwardingRuleRequest{
			Project:        resourceInfo.Project,
			Region:         resourceInfo.Region,
			ForwardingRule: resourceInfo.Name,
		})
		if err != nil {
			return "", "", fmt.Errorf("unable to get forwarding rule: %w", err)
		}
		ruleURI = *forwardingRule.SelfLink
	} else {
		addrRequest := computepb.InsertGlobalAddressRequest{
			Project:         resourceInfo.Project,
			AddressResource: addressResource,
		}
		addrRequest.AddressResource.Purpose = proto.String(addressPurpose)
		addrRequest.AddressResource.Network = proto.String(getVpcUrl(resourceInfo.Project, resourceInfo.Namespace))
		addrRequest.AddressResource.Address = proto.String(strings.Split(additionalAddress, "/")[0]) // TODO: use variable length to get a /32

		addrOp, err := r.globalAddressesClient.Insert(ctx, &addrRequest)
		if err != nil {
			return "", "", fmt.Errorf("unable to insert address: %w", err)
		}
		if err = addrOp.Wait(ctx); err != nil {
			return "", "", fmt.Errorf("unable to wait for the operation: %w", err)
		}

		// Get the allocated address
		getAddressReq := computepb.GetGlobalAddressRequest{
			Project: resourceInfo.Project,
			Address: addressName,
		}
		addr, err := r.globalAddressesClient.Get(ctx, &getAddressReq)
		if err != nil {
			return "", "", fmt.Errorf("unable to get address: %w", err)
		}
		addressURL = *addr.SelfLink
		address = *addr.Address

		// Create a forwarding rule for the endpoint
		forwardingRuleRequest := computepb.InsertGlobalForwardingRuleRequest{
			Project: resourceInfo.Project,
			ForwardingRuleResource: &computepb.ForwardingRule{
				Name:      proto.String(resourceInfo.Name),
				IPAddress: proto.String(addressURL),
				Network:   proto.String(getVpcUrl(resourceInfo.Project, resourceInfo.Namespace)),
				Target:    proto.String(service.Bundle),
			},
		}

		forwardingRuleOp, err := r.globalForwardingClient.Insert(ctx, &forwardingRuleRequest)
		if err != nil {
			return "", "", fmt.Errorf("unable to insert forwarding rule: %w", err)
		}
		if err = forwardingRuleOp.Wait(ctx); err != nil {
			return "", "", fmt.Errorf("unable to wait for the operation: %w", err)
		}

		// Get the URI of the forwarding rule created
		forwardingRule, err := r.globalForwardingClient.Get(ctx, &computepb.GetGlobalForwardingRuleRequest{
			Project:        resourceInfo.Project,
			ForwardingRule: resourceInfo.Name,
		})
		if err != nil {
			return "", "", fmt.Errorf("unable to get forwarding rule: %w", err)
		}
		ruleURI = *forwardingRule.SelfLink
	}

	return ruleURI, address, nil
}
