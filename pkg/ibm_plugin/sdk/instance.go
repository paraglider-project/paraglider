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

package ibm

import (
	"strings"
	"time"

	"github.com/IBM/vpc-go-sdk/vpcv1"

	utils "github.com/NetSys/invisinets/pkg/utils"
)

// CreateInstance creates a VM in the specified subnet and zone.
// if subnet id isn't specified, the VM will be created
// on a random subnet in the selected zone.
func (c *CloudClient) CreateInstance(vpcID, subnetID string,
	instanceOptions *vpcv1.CreateInstanceOptions) (*vpcv1.Instance, error) {
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

	instance, err := c.createInstance(keyID, vpcID, subnetID, instanceOptions, securityGroup)
	if err != nil {
		utils.Log.Println("Failed to launch instance with error:\n", err)
		return nil, err
	}
	return instance, nil
}

func (c *CloudClient) createInstance(keyID, vpcID, subnetID string, instanceOptions *vpcv1.CreateInstanceOptions, securityGroup *vpcv1.SecurityGroup) (
	*vpcv1.Instance, error) {
	instanceTags := []string{vpcID}

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

	err = c.attachTag(instance.CRN, instanceTags)
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

// GetInstanceSecurityGroups returns security group IDs that are associated with the VM's network interfaces
func (c *CloudClient) GetInstanceSecurityGroups(name string) ([]string, error) {
	var sgGroups []string

	vmID, err := c.GetInstanceID(name)
	if err != nil {
		return nil, err
	}

	nics, _, err := c.vpcService.ListInstanceNetworkInterfaces(
		&vpcv1.ListInstanceNetworkInterfacesOptions{InstanceID: &vmID})
	if err != nil {
		return nil, err
	}
	for _, nic := range nics.NetworkInterfaces {
		for _, sg := range nic.SecurityGroups {
			sgGroups = append(sgGroups, *sg.ID)
		}
	}
	return sgGroups, nil
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

// VMToVPCID returns VPC id of specified instance
func (c *CloudClient) VMToVPCID(vmID string) (string, error) {
	instance, _, err := c.vpcService.GetInstance(
		&vpcv1.GetInstanceOptions{ID: &vmID})
	if err != nil {
		return "", err
	}
	return *instance.VPC.ID, nil
}
