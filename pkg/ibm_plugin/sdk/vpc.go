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

	"github.com/IBM/vpc-go-sdk/vpcv1"

	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

const vpcType = "vpc"

const SharedVPC = "shared"

// CreateVPC creates a Paraglider VPC for a region resources are tagged.
func (c *CloudClient) CreateVPC(tags []string, exclusive bool) (*vpcv1.VPC, error) {
	var prefixManagement string

	vpcName := GenerateResourceName(vpcType)

	if !exclusive {
		tags = append(tags, SharedVPC)
	}

	// Prefix Management is done when subnet are created separately
	prefixManagement = vpcv1.CreateVPCOptionsAddressPrefixManagementManualConst

	options := vpcv1.CreateVPCOptions{
		Name:                   &vpcName,
		ResourceGroup:           c.resourceGroup,
		AddressPrefixManagement: &prefixManagement,
	}

	vpc, response, err := c.vpcService.CreateVPC(&options)
	if err != nil {
		utils.Log.Println("Failed to create VPC with error:", err,
			"\nResponse:\n", response)
		return nil, err
	}
	err = c.attachTag(vpc.CRN, tags)
	if err != nil {
		utils.Log.Print("Failed to tag VPC with error:", err)
		return nil, err
	}
	utils.Log.Printf("Created VPC: %v with ID: %v", *vpc.Name, *vpc.ID)
	return vpc, nil
}

// TerminateVPC terminates a vpc, deleting its associated instances and subnets
func (c *CloudClient) TerminateVPC(vpcID string) error {
	// Fetch instances of specified VPC
	instanceList, _, err := c.vpcService.ListInstances(&vpcv1.ListInstancesOptions{
		VPCID:           &vpcID,
		ResourceGroupID: c.resourceGroup.ID,
	})
	if err != nil {
		return err
	}
	// TODO: execute instance deletion and polling concurrently
	// delete floating ips marked "recyclable"
	for _, instance := range instanceList.Instances {
		c.deleteFloatingIPsOfVM(&instance)
		// delete current VM
		_, err := c.vpcService.DeleteInstance(
			&vpcv1.DeleteInstanceOptions{ID: instance.ID})
		if err != nil {
			return err
		}
	}
	// wait for instances deletion process to end
	for _, instance := range instanceList.Instances {
		if !c.waitForInstanceRemoval(*instance.ID) {
			return fmt.Errorf("failed to remove instance within the alloted time frame")
		}
		utils.Log.Printf("Deleted instance with ID: %v", *instance.ID)
	}

	err = c.DeleteSubnets(vpcID)
	if err != nil {
		return err
	}

	// Delete VPC
	_, err = c.vpcService.DeleteVPC(&vpcv1.DeleteVPCOptions{
		ID: &vpcID,
	})
	if err != nil {
		return err
	}

	utils.Log.Printf("VPC %v deleted successfully", vpcID)
	return nil
}

// GetVPCByID returns vpc data of specified vpc
func (c *CloudClient) GetVPCByID(vpcID string) (*vpcv1.VPC, error) {
	vpc, response, err := c.vpcService.GetVPC(&vpcv1.GetVPCOptions{
		ID: &vpcID,
	})
	if err != nil {
		utils.Log.Println("Failed to retrieve VPC, Error: ", err, "\nResponse\n", response)
		return nil, err
	}
	return vpc, nil
}

// returns CIDR of VPC
func (c *CloudClient) GetVpcCIDR(vpcID string) ([]string, error) {
	// aggregate addresses of subnets in VPC 
	subnets, err := c.GetSubnetsInVpcRegionBound(vpcID)
	if err != nil {
		return nil, err
	}
	var addresses = make([]string, len(subnets))
	for i, subnet := range subnets {
		address, err := c.GetSubnetCIDR(*subnet.ID)
		if err != nil {
			return nil, err
		}
		addresses[i] = address
	}

	return addresses, nil
}
