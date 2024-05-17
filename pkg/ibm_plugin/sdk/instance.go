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
	"fmt"
	"strings"
	"time"

	"github.com/IBM/vpc-go-sdk/vpcv1"

	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

// CreateInstance creates a VM in the specified subnet and zone.
func (c *CloudClient) CreateInstance(vpcID, subnetID string,
	instanceOptions *vpcv1.CreateInstanceOptions, tags []string) (*vpcv1.Instance, error) {
	keyID, err := c.setupAuth()
	if err != nil {
		utils.Log.Println("failed to setup authentication")
		return nil, err
	}

	securityGroup, err := c.createSecurityGroup(vpcID)
	if err != nil {
		utils.Log.Println("Failed to create security group for VM with error: ", err)
		return nil, err
	}

	instance, err := c.createInstance(keyID, subnetID, instanceOptions, securityGroup, tags)
	if err != nil {
		utils.Log.Println("Failed to launch instance with error:\n", err)
		return nil, err
	}
	return instance, nil
}

func (c *CloudClient) createInstance(keyID, subnetID string, instanceOptions *vpcv1.CreateInstanceOptions, securityGroup *vpcv1.SecurityGroup, tags []string) (
	*vpcv1.Instance, error) {

	sgGrps := []vpcv1.SecurityGroupIdentityIntf{
		&vpcv1.SecurityGroupIdentityByID{ID: securityGroup.ID}}

	subnetIdentity := vpcv1.SubnetIdentityByID{ID: &subnetID}

	nicPrototype := vpcv1.NetworkInterfacePrototype{
		Subnet:         &subnetIdentity,
		SecurityGroups: sgGrps,
	}
	keyIdentity := vpcv1.KeyIdentityByID{ID: &keyID}
	proto := instanceOptions.InstancePrototype

	proto.(*vpcv1.InstancePrototypeInstanceByImage).Keys = []vpcv1.KeyIdentityIntf{&keyIdentity}
	proto.(*vpcv1.InstancePrototypeInstanceByImage).PrimaryNetworkInterface = &nicPrototype
	proto.(*vpcv1.InstancePrototypeInstanceByImage).ResourceGroup = c.resourceGroup

	utils.Log.Printf("Creating instance : %+v", instanceOptions.InstancePrototype)

	instance, _, err := c.vpcService.CreateInstance(instanceOptions)
	if err != nil {
		return nil, err
	}
	utils.Log.Printf("VM %s was launched with ID: %v", *instance.Name, *instance.ID)

	err = c.attachTag(instance.CRN, tags)
	if err != nil {
		utils.Log.Print("Failed to tag VM with error:", err)
		return nil, err
	}

	// add VM ID tag to security group
	err = c.attachTag(securityGroup.CRN, []string{*instance.ID})
	if err != nil {
		utils.Log.Print("Failed to tag SG with error:", err)
		return nil, err
	}

	return instance, nil
}

// GetInstanceSecurityGroupID returns the security group ID that's associated with the VM's network interfaces
func (c *CloudClient) GetInstanceSecurityGroupID(id string) (string, error) {

	nics, _, err := c.vpcService.ListInstanceNetworkInterfaces(
		&vpcv1.ListInstanceNetworkInterfacesOptions{InstanceID: &id})
	if err != nil {
		return "", err
	}
	for _, nic := range nics.NetworkInterfaces {
		for _, sg := range nic.SecurityGroups {
			if IsParagliderResource(*sg.Name) {
				// A VM is only ever associated with a single paraglider SG
				return *sg.ID, nil
			}
		}
	}
	return "", fmt.Errorf("no paraglider SG is associated with the specified instance")
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

func (c *CloudClient) GetInstanceReservedIP(vmID string) (string, error) {
	// in case the instance recently launched, poll to wait for ip to be assigned to the instance.
	if isInstanceReady, err := c.PollInstanceReady(vmID); isInstanceReady {
		vmData, _, err := c.vpcService.GetInstance(&vpcv1.GetInstanceOptions{ID: &vmID})
		if err != nil {
			return "", err
		}
		privateIP := *vmData.NetworkInterfaces[0].PrimaryIP.Address
		return privateIP, nil
	} else {
		return "", err
	}
}

// returns True once the instance is ready.
func (c *CloudClient) PollInstanceReady(vmID string) (bool, error) {
	sleepDuration := 10 * time.Second
	for tries := 15; tries > 0; tries-- {
		res, _, err := c.vpcService.GetInstance(c.vpcService.NewGetInstanceOptions(vmID))
		if err != nil {
			return false, err
		}
		if *res.Status == "running" {
			return true, nil
		}
		time.Sleep(sleepDuration)
	}
	return false, fmt.Errorf("Instance ID: %v failed to launch within the alloted time.", vmID)
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

// VMToVPCObject returns VPC data of specified instance
func (c *CloudClient) VMToVPCObject(vmID string) (*vpcv1.VPCReference, error) {
	instance, _, err := c.vpcService.GetInstance(
		&vpcv1.GetInstanceOptions{ID: &vmID})
	if err != nil {
		return nil, err
	}
	return instance.VPC, nil
}

// returns True if an instance resides inside the specified namespace
// region is an optional argument used to increase effectiveness of resource search
func (c *CloudClient) IsInstanceInNamespace(InstanceName, namespace, region string) (bool, error) {
	resourceQuery := ResourceQuery{}
	vmData, err := c.getInstanceDataFromID(InstanceName)
	if err != nil {
		return false, err
	}

	// add VM's CRN and region to search attributes
	resourceQuery.CRN = *vmData.CRN
	if region != "" {
		resourceQuery.Region = region
	}

	// look for a VM with the specified CRN in the specified namespace.
	taggedVMData, err := c.GetParagliderTaggedResources(VM, []string{namespace},
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

// GetInstanceID returns ID of the instance matching the specified name
func (c *CloudClient) GetInstanceData(name string) (*vpcv1.Instance, error) {
	options := &vpcv1.ListInstancesOptions{Name: &name}
	collection, _, err := c.vpcService.ListInstances(options)
	if err != nil {
		return nil, err
	}
	if len(collection.Instances) == 0 {
		return nil, fmt.Errorf("instance %s not found", name)
	}
	return &collection.Instances[0], nil
}

// GetInstanceID returns ID of the instance matching the specified name
func (c *CloudClient) getInstanceDataFromID(id string) (*vpcv1.Instance, error) {
	options := &vpcv1.GetInstanceOptions{ID: &id}
	instance, _, err := c.vpcService.GetInstance(options)
	if err != nil {
		return nil, err
	}
	return instance, nil
}
