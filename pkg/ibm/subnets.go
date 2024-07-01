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
	"strings"

	"github.com/IBM/vpc-go-sdk/vpcv1"

	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

const subnetType = "subnet"

// CreateSubnet creates subnet in specified vpc and zone.
func (c *CloudClient) CreateSubnet(
	vpcID, zone, addressSpace string, tags []string) (*vpcv1.Subnet, error) {
	zone = strings.TrimSpace(zone)

	zoneIdentity := vpcv1.ZoneIdentity{Name: &zone}
	vpcIdentity := vpcv1.VPCIdentityByID{ID: &vpcID}
	subnetName := generateResourceName(subnetType)

	// Before creating a subnet, we must create an address prefix in the VPC
	addressPrefixOptions := vpcv1.CreateVPCAddressPrefixOptions{
		VPCID: &vpcID,
		CIDR:  &addressSpace,
		Zone:  &zoneIdentity,
	}

	_, _, err := c.vpcService.CreateVPCAddressPrefix(&addressPrefixOptions)
	if err != nil {
		return nil, err
	}

	subnetPrototype := vpcv1.SubnetPrototype{
		Zone:          &zoneIdentity,
		Ipv4CIDRBlock: &addressSpace,
		VPC:           &vpcIdentity,
		Name:          &subnetName,
		ResourceGroup: c.resourceGroup,
	}
	options := vpcv1.CreateSubnetOptions{SubnetPrototype: &subnetPrototype}
	subnet, _, err := c.vpcService.CreateSubnet(&options)
	if err != nil {
		utils.Log.Println("Failed to create subnet with error:\n", err)
		return nil, err
	}
	utils.Log.Printf("Created subnet %v with id %v", subnetName, *subnet.ID)

	err = c.attachTag(subnet.CRN, tags)
	if err != nil {
		utils.Log.Print("Failed to tag subnet with error:", err)
		return nil, err
	}

	// TODO @cohen-j-omer: If instances require direct outbound traffic, attach subnet to a gateway:
	// 1. if a public gateway doesn't already exist in the zone, create it.
	// 2. attach subnet to gateway.
	return subnet, nil
}

// GetSubnetsInVPC returns all paraglider subnets in the specified VPC.
// NOTE: unlike GetSubnetsInVpcRegionBound isn't reliant on the vpcService's region.
func (c *CloudClient) GetSubnetsInVPC(vpcID string) ([]resourceData, error) {
	subnets, err := c.GetParagliderTaggedResources(SUBNET, []string{vpcID}, resourceQuery{})
	if err != nil {
		return nil, err
	}
	return subnets, nil
}

// GetSubnetsInVpcRegionBound returns all subnets in vpc, user's and paraglider'
// in the region set by the client.
// NOTES: before invoking this function Set VPC client to the region the VPC is located in.
//
//	This function returns more info in contrast to GetSubnetsInVPC.
func (c *CloudClient) GetSubnetsInVpcRegionBound(vpcID string) ([]vpcv1.Subnet, error) {
	subnetOptions := &vpcv1.ListSubnetsOptions{VPCID: &vpcID}
	subnets, resp, err := c.vpcService.ListSubnets(subnetOptions)
	if err != nil {
		utils.Log.Printf("error fetching subnets: %+v", resp)
		return nil, err
	}
	return subnets.Subnets, nil
}

// returns true if the specified remote (CIDR/IP) is a subset of the specified VPC's address space.
// NOTE: address space refers to that of the subnets within the VPC's, not to its address prefixes.
func (c *CloudClient) IsRemoteInVPC(vpcID string, remote string) (bool, error) {
	subnets, err := c.GetSubnetsInVpcRegionBound(vpcID)
	if err != nil {
		return false, err
	}
	// check whether the remote cidr belongs to one of the VPC's subnets
	for _, subnet := range subnets {
		subnetSpace, err := c.GetSubnetCIDR(*subnet.ID)
		if err != nil {
			return false, err
		}
		isSubset, err := IsRemoteInCIDR(remote, subnetSpace)
		if err != nil {
			return false, err
		}
		if isSubset {
			return true, nil
		}
	}
	// remote doesn't reside in any of the VPCs' subnets.
	return false, nil
}

// returns true if any of the specified vpc's subnets' address spaces overlap with given cidr
// NOTE: before invoking this function Set VPC client to the region the VPC is located in.
func (c *CloudClient) DoSubnetsInVPCOverlapCIDR(vpcID string,
	CIDR string) (bool, error) {
	subnets, err := c.GetSubnetsInVpcRegionBound(vpcID)
	if err != nil {
		return true, err
	}

	for _, subnet := range subnets {
		doesOverlap, err := utils.DoCIDROverlap(*subnet.Ipv4CIDRBlock, CIDR)
		if err != nil {
			return true, err
		}
		if doesOverlap {
			return true, nil
		}
	}
	return false, nil
}

// DeleteSubnets deletes all subnets in the specified VPC.
// NOTE: before invoking this function Set VPC client to the region the VPC is located in.
func (c *CloudClient) DeleteSubnets(vpcID string) error {
	subnets, err := c.GetSubnetsInVpcRegionBound(vpcID)
	if err != nil {
		return err
	}
	for _, subnet := range subnets {
		options := &vpcv1.DeleteSubnetOptions{ID: subnet.ID}
		_, err := c.vpcService.DeleteSubnet(options)
		if err != nil {
			utils.Log.Printf("Failed to delete subnet %v with error:%v",
				subnet.ID, err)
			return err
		}
		utils.Log.Printf("deleted subnet with ID: %v", subnet.ID)
	}
	return nil
}

// GetSubnetCIDR returns address space of subnet
// NOTE: before invoking this function Set VPC client to the region the VPC is located in.
func (c *CloudClient) GetSubnetCIDR(subnetID string) (string, error) {
	subnet, _, err := c.vpcService.GetSubnet(c.vpcService.NewGetSubnetOptions(subnetID))
	if err != nil {
		return "", err
	}
	return *subnet.Ipv4CIDRBlock, nil
}
