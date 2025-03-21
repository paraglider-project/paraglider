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

package ibm

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	k8sv1 "github.com/IBM-Cloud/container-services-go-sdk/kubernetesserviceapiv1"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"

	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

const (
	// InstanceResourceType is an instance type of resource
	InstanceResourceType = "instance"
	instanceReadyState   = "running"

	// ClusterResourceType is a cluster type of resource
	ClusterResourceType = "cluster"
	ClusterReadyState   = "normal"

	// PrivateEndpointType is a private endpoint gateway type of resource
	PrivateEndpointResourceType = "endpoint"
	endpointReadyState          = "stable"

	// ClusterReadyState is the ideal running state of a cluster
	clusterType = "vpc-gen2"
	defaultZone = "us-east-1"
	ipResType   = "ip"
)

// ResourceResponse contains the required resource fields to be returned after creation of a resource
type ResourceResponse struct {
	// Name is the resource name
	Name string
	// URI is the unique resource identifier of the format /resourcegroup/{id}/zone/{zone}/{resource_type}/{resource_id}
	URI string
	// IP is the endpoint IP of the resource
	IP string
}

// ResourceIntf is a common resource interface to be implemented for multiple resource types such as instance, k8s cluster, etc.
type ResourceIntf interface {
	CreateResource(name, vpcID, subnetID string, tags []string, resourceDesc []byte) (*ResourceResponse, error)
	IsInNamespace(namespace, region string) (bool, error)
	IsExclusiveNetworkNeeded() bool
	GetID() string
	GetSecurityGroupID() (string, error)
	GetVPC() (*vpcv1.VPCReference, error)
	GetTypeName() string
}

// ResourceInstanceType is the handler for instance type resources
type ResourceInstanceType struct {
	ResourceIntf
	ID     string
	client *CloudClient
}

// ResourceClusterType is the handler for cluster type resources
type ResourceClusterType struct {
	ResourceIntf
	ID     string
	client *CloudClient
}

// ResourcePrivateEndpointType is the handler for private endpoint resources
type ResourcePrivateEndpointType struct {
	ResourceIntf
	ID     string
	client *CloudClient
}

func (i *ResourceInstanceType) createURI(resGroup, zone, resName string) string {
	return fmt.Sprintf("/resourcegroup/%s/zone/%s/%s/%s", resGroup, zone, InstanceResourceType, resName)
}

func (i *ResourceInstanceType) getCRN() (*vpcv1.Instance, error) {
	options := &vpcv1.GetInstanceOptions{ID: &i.ID}
	instance, _, err := i.client.vpcService.GetInstance(options)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func (i *ResourceInstanceType) getResourceOptions(resourceDesc []byte) (*vpcv1.CreateInstanceOptions, error) {
	instanceOptions := vpcv1.CreateInstanceOptions{
		InstancePrototype: &vpcv1.InstancePrototypeInstanceByImage{
			Image:   &vpcv1.ImageIdentityByID{},
			Zone:    &vpcv1.ZoneIdentityByName{},
			Profile: &vpcv1.InstanceProfileIdentityByName{},
		},
	}
	err := json.Unmarshal(resourceDesc, &instanceOptions)
	if err != nil {
		return nil, err
	}
	return &instanceOptions, nil
}

func (i *ResourceInstanceType) getInstanceIP() (string, error) {
	// in case the instance recently launched, poll to wait for ip to be assigned to the instance.
	var err error
	var isInstanceReady bool
	if isInstanceReady, err = i.waitForReady(); isInstanceReady {
		vmData, _, err := i.client.vpcService.GetInstance(&vpcv1.GetInstanceOptions{ID: &i.ID})
		if err != nil {
			return "", err
		}
		privateIP := *vmData.NetworkInterfaces[0].PrimaryIP.Address
		return privateIP, nil
	}
	return "", err
}

func (i *ResourceInstanceType) waitForReady() (bool, error) {
	sleepDuration := 10 * time.Second
	for tries := 15; tries > 0; tries-- {
		res, _, err := i.client.vpcService.GetInstance(i.client.vpcService.NewGetInstanceOptions(i.ID))
		if err != nil {
			return false, err
		}
		if *res.Status == instanceReadyState {
			return true, nil
		}
		time.Sleep(sleepDuration)
	}
	return false, fmt.Errorf("instance ID %v failed to launch within the alloted time", i.ID)
}

func (i *ResourceInstanceType) GetTypeName() string {
	return InstanceResourceType
}

// CreateResource create an instance
func (i *ResourceInstanceType) CreateResource(name, vpcID, subnetID string, tags []string, resourceDesc []byte) (*ResourceResponse, error) {
	instanceOptions, err := i.getResourceOptions(resourceDesc)
	if err != nil {
		utils.Log.Println("failed to get create instance options: ", err)
		return nil, err
	}
	keyID, err := i.client.setupAuth()
	if err != nil {
		utils.Log.Println("failed to setup authentication: ", err)
		return nil, err
	}

	securityGroup, err := i.client.createSecurityGroup(vpcID)
	if err != nil {
		utils.Log.Println("Failed to create security group for instance with error: ", err)
		return nil, err
	}

	sgGrps := []vpcv1.SecurityGroupIdentityIntf{
		&vpcv1.SecurityGroupIdentityByID{ID: securityGroup.ID}}

	subnetIdentity := vpcv1.SubnetIdentityByID{ID: &subnetID}

	nicPrototype := vpcv1.NetworkInterfacePrototype{
		Subnet:         &subnetIdentity,
		SecurityGroups: sgGrps,
	}
	keyIdentity := vpcv1.KeyIdentityByID{ID: &keyID}
	proto := instanceOptions.InstancePrototype

	proto.(*vpcv1.InstancePrototypeInstanceByImage).Name = &name
	proto.(*vpcv1.InstancePrototypeInstanceByImage).Keys = []vpcv1.KeyIdentityIntf{&keyIdentity}
	proto.(*vpcv1.InstancePrototypeInstanceByImage).PrimaryNetworkInterface = &nicPrototype
	proto.(*vpcv1.InstancePrototypeInstanceByImage).ResourceGroup = i.client.resourceGroup

	utils.Log.Printf("Creating instance : %+v", instanceOptions.InstancePrototype)

	instance, _, err := i.client.vpcService.CreateInstance(instanceOptions)
	if err != nil {
		return nil, err
	}
	utils.Log.Printf("Instance %s was launched with ID: %v", *instance.Name, *instance.ID)

	i.ID = *instance.ID
	err = i.client.attachTag(instance.CRN, tags)
	if err != nil {
		utils.Log.Print("Failed to tag instance with error:", err)
		return nil, err
	}
	// add instance ID tag to security group
	err = i.client.attachTag(securityGroup.CRN, []string{*instance.ID})
	if err != nil {
		utils.Log.Print("Failed to tag SG with error:", err)
		return nil, err
	}

	reservedIP, err := i.getInstanceIP()

	if err != nil {
		return nil, err
	}

	resp := ResourceResponse{Name: *instance.Name, URI: i.createURI(*i.client.resourceGroup.ID, *instance.Zone.Name, *instance.ID), IP: reservedIP}

	return &resp, nil
}

// IsInNamespace returns True if an instance resides inside the specified namespace
// region is an optional argument used to increase effectiveness of resource search
func (i *ResourceInstanceType) IsInNamespace(namespace, region string) (bool, error) {
	resourceQuery := resourceQuery{}
	vmData, err := i.getCRN()
	if err != nil {
		return false, err
	}

	// add VM's CRN and region to search attributes
	resourceQuery.CRN = *vmData.CRN
	if region != "" {
		resourceQuery.Region = region
	}

	// look for a VM with the specified CRN in the specified namespace.
	taggedVMData, err := i.client.GetParagliderTaggedResources(vpcv1.InstanceResourceTypeInstanceConst, []string{namespace},
		resourceQuery)
	if err != nil {
		return false, err
	}
	if len(taggedVMData) == 1 {
		// should return True only if exactly 1 result was retrieved,
		// since CRN is included in search.
		return true, nil
	}

	return false, nil
}

// IsExclusiveNetworkNeeded indicates if this resource needs an exclusive VPC to be provisioned
func (i *ResourceInstanceType) IsExclusiveNetworkNeeded() bool {
	return false
}

// GetID fetches the identifier of instance
func (i *ResourceInstanceType) GetID() string {
	return i.ID
}

// GetSecurityGroupID returns the security group ID that's associated with the instance's network interfaces
func (i *ResourceInstanceType) GetSecurityGroupID() (string, error) {
	nics, _, err := i.client.vpcService.ListInstanceNetworkInterfaces(
		&vpcv1.ListInstanceNetworkInterfacesOptions{InstanceID: &i.ID})
	if err != nil {
		return "", err
	}
	for _, nic := range nics.NetworkInterfaces {
		for _, sg := range nic.SecurityGroups {
			if isParagliderResource(*sg.Name) {
				// A VM is only ever associated with a single paraglider SG
				return *sg.ID, nil
			}
		}
	}
	return "", fmt.Errorf("no paraglider SG is associated with the specified instance")
}

// GetVPC returns VPC data of specified instance
func (i *ResourceInstanceType) GetVPC() (*vpcv1.VPCReference, error) {
	instance, _, err := i.client.vpcService.GetInstance(
		&vpcv1.GetInstanceOptions{ID: &i.ID})
	if err != nil {
		return nil, err
	}
	return instance.VPC, nil
}

func (c *ResourceClusterType) createURI(resGroup, zone, resName string) string {
	return fmt.Sprintf("/resourcegroup/%s/zone/%s/%s/%s", resGroup, zone, ClusterResourceType, resName)
}

func (c *ResourceClusterType) getCRN() (string, error) {
	options := c.client.k8sService.NewVpcGetClusterOptions(c.ID)
	options.XAuthResourceGroup = c.client.resourceGroup.ID
	cl, _, err := c.client.k8sService.VpcGetCluster(options)
	if err != nil {
		return "", err
	}
	return *cl.Crn, nil
}

func (c *ResourceClusterType) getResourceOptions(resourceDesc []byte) (*k8sv1.VpcCreateClusterOptions, error) {
	clusterOptions := k8sv1.VpcCreateClusterOptions{}

	err := json.Unmarshal(resourceDesc, &clusterOptions)
	if err != nil {
		return nil, err
	}

	return &clusterOptions, nil
}

// returns True once the Cluster is ready.
func (c *ResourceClusterType) waitForReady() (bool, error) {
	sleepDuration := 60 * time.Second
	for tries := 100; tries > 0; tries-- {
		res, _, err := c.client.k8sService.VpcGetCluster(c.client.k8sService.NewVpcGetClusterOptions(c.ID))
		if err != nil {
			return false, err
		}
		if *res.State == ClusterReadyState {
			return true, nil
		}

		time.Sleep(sleepDuration)
	}
	return false, fmt.Errorf("cluster ID %v failed to launch within the alloted time", c.ID)
}

func (i *ResourceClusterType) GetTypeName() string {
	return ClusterResourceType
}

// CreateResource creates a cluster
func (c *ResourceClusterType) CreateResource(name, vpcID, subnetID string, tags []string, resourceDesc []byte) (*ResourceResponse, error) {
	clusterOptions, err := c.getResourceOptions(resourceDesc)
	if err != nil {
		utils.Log.Println("failed to get create instance options: ", err)
		return nil, err
	}

	clusterOptions.Name = &name
	clusterOptions.XAuthResourceGroup = c.client.resourceGroup.ID
	clusterOptions.Provider = core.StringPtr(clusterType)
	clusterOptions.WorkerPool.VpcID = &vpcID
	clusterOptions.WorkerPool.Zones[0].SubnetID = &subnetID

	// TODO @praveingk : Support multi-zone Kubernetes
	utils.Log.Printf("Creating cluster : %+v", clusterOptions)

	cluster, resp, err := c.client.k8sService.VpcCreateCluster(clusterOptions)
	if err != nil {
		fmt.Printf("Failed to create cluster %+v :\n %s\n", *resp, err.Error())
		return nil, err
	}
	utils.Log.Printf("Created Cluster : %s\n", *cluster.ClusterID)

	c.ID = *cluster.ClusterID
	clusterCRN, err := c.getCRN()
	if err != nil {
		utils.Log.Print("Failed to get CRN of cluster:", err)
		return nil, err
	}
	err = c.client.attachTag(&clusterCRN, tags)
	if err != nil {
		utils.Log.Print("Failed to tag cluster with error:", err)
		return nil, err
	}

	// Get Cluster VPC Security group
	vpcSg, err := c.client.getDefaultSecurityGroup(vpcID)
	if err != nil {
		utils.Log.Print("Failed to get SG CRN:", err)
		return nil, err
	}

	err = c.client.attachTag(vpcSg.CRN, []string{*cluster.ClusterID, vpcID})
	if err != nil {
		utils.Log.Print("Failed to tag SG with error:", err)
		return nil, err
	}

	clusterCIDR, err := c.client.GetSubnetCIDR(subnetID)
	if err != nil {
		utils.Log.Print("Failed to get subnet CIDR:", err)
		return nil, err
	}

	if clusterReady, err := c.waitForReady(); !clusterReady || err != nil {
		utils.Log.Print("Failed to get cluster to ready state:", err)
		return nil, fmt.Errorf("cluster not ready %v", err.Error())
	}

	return &ResourceResponse{Name: name, URI: c.createURI(*c.client.resourceGroup.ID, *clusterOptions.WorkerPool.Zones[0].ID, *cluster.ClusterID), IP: clusterCIDR}, nil
}

// IsInNamespace checks if the cluster is in the namespace
func (c *ResourceClusterType) IsInNamespace(namespace, region string) (bool, error) {
	resourceQuery := resourceQuery{}
	clusterCRN, err := c.getCRN()
	if err != nil {
		return false, err
	}

	// add cluster's CRN and region to search attributes
	resourceQuery.CRN = clusterCRN
	if region != "" {
		resourceQuery.Region = region
	}

	// look for cluster with the specified CRN in the specified namespace.
	taggedVMData, err := c.client.GetParagliderTaggedResources(CLUSTER, []string{namespace},
		resourceQuery)
	if err != nil {
		return false, err
	}
	if len(taggedVMData) == 1 {
		// should return True only if exactly 1 result was retrieved,
		// since CRN is included in search.
		return true, nil
	}

	return false, nil
}

// IsExclusiveNetworkNeeded indicates if this resource needs an exclusive VPC to be provisioned
func (c *ResourceClusterType) IsExclusiveNetworkNeeded() bool {
	return true
}

// GetID fetches the identifier of instance
func (c *ResourceClusterType) GetID() string {
	return c.ID
}

// GetVPC returns the VPC reference of the endpoint gateway of the cluster
func (c *ResourceClusterType) GetVPC() (*vpcv1.VPCReference, error) {
	// A Cluster would have a security group with prefix of 'kube-',
	// We infer the VPC of the cluster using the VPC of this security group
	clusterSG := "kube-" + c.ID
	sgs, _, err := c.client.vpcService.ListSecurityGroups(c.client.vpcService.NewListSecurityGroupsOptions())
	if err != nil {
		return nil, err
	}

	for _, sg := range sgs.SecurityGroups {
		if *sg.Name == clusterSG {
			return sg.VPC, nil
		}
	}
	return nil, fmt.Errorf("unable to find the VPC of cluster %s", c.ID)
}

func (e *ResourcePrivateEndpointType) createURI(resGroup, zone, resName string) string {
	return fmt.Sprintf("/resourcegroup/%s/zone/%s/%s/%s", resGroup, zone, PrivateEndpointResourceType, resName)
}

func (i *ResourcePrivateEndpointType) getCRN() (string, error) {
	options := &vpcv1.GetEndpointGatewayOptions{ID: &i.ID}
	endpoint, _, err := i.client.vpcService.GetEndpointGateway(options)
	if err != nil {
		return "", err
	}
	return *endpoint.CRN, nil
}

func (e *ResourcePrivateEndpointType) getEndpointIP() (string, error) {
	// in case the private endpoint recently launched, poll to wait for ip to be assigned to the private endpoint.
	var err error
	var isEndpointReady bool
	if isEndpointReady, err = e.waitForReady(); isEndpointReady {
		eData, _, err := e.client.vpcService.GetEndpointGateway(e.client.vpcService.NewGetEndpointGatewayOptions(e.ID))
		if err != nil {
			return "", err
		}
		privateIP := *eData.Ips[0].Address
		return privateIP, nil
	}
	return "", err
}

func (e *ResourcePrivateEndpointType) getResourceOptions(resourceDesc []byte) (*vpcv1.CreateEndpointGatewayOptions, error) {
	endpointGatewayOptions := vpcv1.CreateEndpointGatewayOptions{
		Target: &vpcv1.EndpointGatewayTargetPrototype{},
	}

	err := json.Unmarshal(resourceDesc, &endpointGatewayOptions)
	if err != nil {
		return nil, err
	}
	return &endpointGatewayOptions, nil
}

func (e *ResourcePrivateEndpointType) waitForReady() (bool, error) {
	sleepDuration := 10 * time.Second
	for tries := 15; tries > 0; tries-- {
		res, _, err := e.client.vpcService.GetEndpointGateway(e.client.vpcService.NewGetEndpointGatewayOptions(e.ID))
		if err != nil {
			return false, err
		}
		if *res.LifecycleState == endpointReadyState {
			return true, nil
		}
		time.Sleep(sleepDuration)
	}
	return false, fmt.Errorf("endpoint gateway ID %v failed to launch within the alloted time", e.ID)
}

func (i *ResourcePrivateEndpointType) GetTypeName() string {
	return PrivateEndpointResourceType
}

// CreateResource create a private endpoint (VPE)
func (e *ResourcePrivateEndpointType) CreateResource(name, vpcID, subnetID string, tags []string, resourceDesc []byte) (*ResourceResponse, error) {
	endpointGatewayOptions, err := e.getResourceOptions(resourceDesc)
	if err != nil {
		utils.Log.Println("failed to get create private endpoint gateway options: ", err)
		return nil, err
	}

	securityGroup, err := e.client.createSecurityGroup(vpcID)
	if err != nil {
		utils.Log.Println("Failed to create security group for instance with error: ", err)
		return nil, err
	}
	endpointGatewayOptions.Name = &name
	endpointGatewayOptions.VPC = &vpcv1.VPCIdentityByID{ID: &vpcID}
	endpointGatewayOptions.ResourceGroup = e.client.resourceGroup
	endpointGatewayOptions.SecurityGroups = []vpcv1.SecurityGroupIdentityIntf{
		&vpcv1.SecurityGroupIdentityByID{ID: securityGroup.ID}}

	ipName := generateResourceName(ipResType)

	createReservedIPOptions := e.client.vpcService.NewCreateSubnetReservedIPOptions(subnetID)
	createReservedIPOptions.Name = &ipName
	resIP, _, err := e.client.vpcService.CreateSubnetReservedIP(createReservedIPOptions)
	if err != nil {
		return nil, err
	}
	utils.Log.Printf("Created IP %s with id %s\n", ipName, *resIP.ID)
	endpointGatewayOptions.Ips = []vpcv1.EndpointGatewayReservedIPIntf{
		&vpcv1.EndpointGatewayReservedIPReservedIPIdentity{ID: resIP.ID}}

	utils.Log.Printf("Creating private endpoint : %+v", endpointGatewayOptions.Target)

	endpointGateway, _, err := e.client.vpcService.CreateEndpointGateway(endpointGatewayOptions)
	if err != nil {
		return nil, err
	}

	utils.Log.Printf("Private Endpoint gateway %s was launched with ID: %v", *endpointGateway.Name, *endpointGateway.ID)

	e.ID = *endpointGateway.ID
	err = e.client.attachTag(endpointGateway.CRN, tags)
	if err != nil {
		utils.Log.Print("Failed to tag instance with error:", err)
		return nil, err
	}

	// add endpoint gateway ID tag to security group
	err = e.client.attachTag(securityGroup.CRN, []string{*endpointGateway.ID})
	if err != nil {
		utils.Log.Print("Failed to tag SG with error:", err)
		return nil, err
	}

	reservedIP, err := e.getEndpointIP()
	if err != nil {
		return nil, err
	}

	subnets, err := e.client.GetSubnetsInVpcRegionBound(vpcID)
	if err != nil {
		return nil, err
	}
	zone := subnets[0].Zone.Name

	resp := ResourceResponse{Name: *endpointGateway.Name, URI: e.createURI(*e.client.resourceGroup.ID, *zone, *endpointGateway.ID), IP: reservedIP}

	return &resp, nil
}

// IsInNamespace checks if the private endpoint is in the namespace
func (e *ResourcePrivateEndpointType) IsInNamespace(namespace, region string) (bool, error) {
	resourceQuery := resourceQuery{}
	endpointCRN, err := e.getCRN()
	if err != nil {
		return false, err
	}

	// add endpoint's CRN and region to search attributes
	resourceQuery.CRN = endpointCRN
	if region != "" {
		resourceQuery.Region = region
	}

	// look for endpoint with the specified CRN in the specified namespace.
	taggedEPData, err := e.client.GetParagliderTaggedResources(ENDPOINT, []string{namespace},
		resourceQuery)
	if err != nil {
		return false, err
	}
	if len(taggedEPData) == 1 {
		// should return True only if exactly 1 result was retrieved,
		// since CRN is included in search.
		return true, nil
	}

	return false, nil
}

// IsExclusiveNetworkNeeded indicates if this resource needs an exclusive VPC to be provisioned
func (e *ResourcePrivateEndpointType) IsExclusiveNetworkNeeded() bool {
	return false
}

// GetID fetches the identifier of instance
func (e *ResourcePrivateEndpointType) GetID() string {
	return e.ID
}

// GetSecurityGroupID returns the security group ID that's associated with the instance's network interfaces
func (e *ResourcePrivateEndpointType) GetSecurityGroupID() (string, error) {
	res, _, err := e.client.vpcService.GetEndpointGateway(e.client.vpcService.NewGetEndpointGatewayOptions(e.ID))
	if err != nil {
		return "", err
	}
	for _, sg := range res.SecurityGroups {
		if isParagliderResource(*sg.Name) {
			return *sg.ID, nil
		}
	}

	return "", fmt.Errorf("no paraglider SG is associated with the specified VPE")
}

// GetVPC returns VPC data of specified instance
func (e *ResourcePrivateEndpointType) GetVPC() (*vpcv1.VPCReference, error) {
	res, _, err := e.client.vpcService.GetEndpointGateway(e.client.vpcService.NewGetEndpointGatewayOptions(e.ID))
	if err != nil {
		return nil, err
	}

	return res.VPC, nil
}

// NOTE: Currently not in use, as public ips are not provisioned.
// deletes floating ips marked recyclable, that are attached to
// any interface associated with given VM
func (c *CloudClient) deleteFloatingIPsOfVM(vm *vpcv1.Instance) {
	recyclableResource := "recyclable" // placeholder indicator

	for _, nic := range vm.NetworkInterfaces {
		options := c.vpcService.NewListInstanceNetworkInterfaceFloatingIpsOptions(*vm.ID, *nic.ID)
		ips, _, err := c.vpcService.ListInstanceNetworkInterfaceFloatingIps(options)
		if err != nil {
			utils.Log.Println(err)
		}
		for _, ip := range ips.FloatingIps {
			if strings.Contains(recyclableResource, *ip.Name) {
				_, err := c.vpcService.DeleteFloatingIP(c.vpcService.NewDeleteFloatingIPOptions(*ip.ID))
				if err != nil {
					utils.Log.Println(err)
				}
				utils.Log.Println("Deleted recyclable IP: ", *ip.Address)
			}
		}
	}
}

// returns true when instance is completely removed from the subnet.
func (c *CloudClient) waitForInstanceRemoval(vmID string) bool {
	sleepDuration := 10 * time.Second
	for tries := 15; tries > 0; tries-- {
		_, _, err := c.vpcService.GetInstance(c.vpcService.NewGetInstanceOptions(vmID))
		if err != nil {
			return true
		}
		time.Sleep(sleepDuration)
	}
	return false
}

// GetResourceHandlerFromDesc gets the resource handler from the resource description
func (c *CloudClient) GetResourceHandlerFromDesc(resourceDesc []byte) (ResourceIntf, error) {
	instanceOptions := vpcv1.CreateInstanceOptions{
		InstancePrototype: &vpcv1.InstancePrototypeInstanceByImage{
			Image:   &vpcv1.ImageIdentityByID{},
			Zone:    &vpcv1.ZoneIdentityByName{},
			Profile: &vpcv1.InstanceProfileIdentityByName{},
		},
	}

	clusterOptions := k8sv1.VpcCreateClusterOptions{}

	endpointGatewayOptions := vpcv1.CreateEndpointGatewayOptions{
		Target: &vpcv1.EndpointGatewayTargetPrototype{},
	}

	err := json.Unmarshal(resourceDesc, &clusterOptions)
	if err == nil && clusterOptions.WorkerPool != nil {
		return &ResourceClusterType{client: c}, nil
	}

	err = json.Unmarshal(resourceDesc, &instanceOptions)
	if err == nil && instanceOptions.InstancePrototype.(*vpcv1.InstancePrototypeInstanceByImage).Zone.(*vpcv1.ZoneIdentityByName).Name != nil {
		return &ResourceInstanceType{client: c}, nil
	}

	err = json.Unmarshal(resourceDesc, &endpointGatewayOptions)
	if err == nil && endpointGatewayOptions.Target.(*vpcv1.EndpointGatewayTargetPrototype).ResourceType != nil {
		return &ResourcePrivateEndpointType{client: c}, nil
	}

	return nil, fmt.Errorf("failed to unmarshal resource description:%+v", err)

}

// GetResourceHandlerFromID gets the resource handler from the resource ID/URI
func (c *CloudClient) GetResourceHandlerFromID(deploymentID string) (ResourceIntf, error) {
	parts := strings.Split(deploymentID, "/")

	if len(parts) >= 5 {
		switch parts[5] {
		case InstanceResourceType:
			return &ResourceInstanceType{ID: parts[6], client: c}, nil
		case ClusterResourceType:
			return &ResourceClusterType{ID: parts[6], client: c}, nil
		case PrivateEndpointResourceType:
			return &ResourcePrivateEndpointType{ID: parts[6], client: c}, nil
		}
	}

	return nil, fmt.Errorf("invalid resource ID format: expected '/resourcegroup/{ResourceGroup}/zone/{zone}/{resource}/{resource_id}', got '%s'", deploymentID)
}
