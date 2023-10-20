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
	"fmt"

	"github.com/IBM/vpc-go-sdk/vpcv1"

	utils "github.com/NetSys/invisinets/pkg/utils"
)

// CreateVPC creates a vpc and a subnet in each zone. resources are tagged.
// if cidr Block isn't specified, auto-generated address prefixes for the zones are chosen,
// other wise the vpc's zones will span over it.
func (c *CloudClient) CreateVPC(vpcName string, cidrBlock string) (*vpcv1.VPC, error) {
	vpcTags := []string{}
	var prefixManagement string
	var addressPrefixes []string
	if vpcName == "" {
		vpcName = GenerateResourceName("vpc")
	}
	if cidrBlock != "" {
		prefixManagement = vpcv1.CreateVPCOptionsAddressPrefixManagementManualConst
	} else {
		prefixManagement = vpcv1.CreateVPCOptionsAddressPrefixManagementAutoConst
	}

	options := vpcv1.CreateVPCOptions{
		Name:                    &vpcName,
		ResourceGroup:           c.resourceGroup,
		AddressPrefixManagement: &prefixManagement,
	}

	vpc, response, err := c.vpcService.CreateVPC(&options)
	if err != nil {
		utils.Log.Println("Failed to create VPC with error:", err,
			"\nResponse:\n", response)
		return nil, err
	}

	if cidrBlock != "" {
		//split the provided cidr block 3-ways and create 3 address prefixes.
		addressPrefixes, err = SplitCIDR(cidrBlock)
		if err != nil {
			return nil, err
		}
		zones, err := GetZonesOfRegion(c.region)
		if err != nil {
			return nil, err
		}

		for i, zone := range zones {
			zoneIdentity := vpcv1.ZoneIdentity{Name: &zone}
			addressPrefixOptions := vpcv1.CreateVPCAddressPrefixOptions{
				VPCID: vpc.ID,
				CIDR:  &addressPrefixes[i],
				Zone:  &zoneIdentity,
			}
			_, _, err = c.vpcService.CreateVPCAddressPrefix(&addressPrefixOptions)
			if err != nil {
				return nil, err
			}
		}
	}

	zones, err := GetZonesOfRegion(c.region)
	if err != nil {
		return nil, err
	}
	addressSpace := ""
	for i, zone := range zones {
		if addressPrefixes != nil {
			addressSpace = addressPrefixes[i]
			_, err := c.CreateSubnet(*vpc.ID, zone, addressSpace)
			if err != nil {
				utils.Log.Println("Failed to create subnet with error:",
					err)
				return nil, err
			}

		}

	}
	err = c.attachTag(vpc.CRN, vpcTags)
	if err != nil {
		utils.Log.Print("Failed to tag VPC with error:", err)
		return nil, err
	}
	utils.Log.Printf("Created VPC: %v with ID: %v", *vpc.Name, *vpc.ID)
	return vpc, nil
}

// TerminateVPC terminates a vpc, deleting its associated instances and subnets
func (c *CloudClient) TerminateVPC(vpcID string) error {
	// fetch instances of specified VPC
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
