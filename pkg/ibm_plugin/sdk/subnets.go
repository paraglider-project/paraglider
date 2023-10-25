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

	"github.com/IBM/vpc-go-sdk/vpcv1"

	utils "github.com/NetSys/invisinets/pkg/utils"
)

const subnetType = "subnet"

// CreateSubnet creates subnet in specified vpc and zone.
// tag subnet with invisinets prefix and vpc ID.
func (c *CloudClient) CreateSubnet(
	vpcID, zone, addressSpace string) (*vpcv1.Subnet, error) {
	subnetTags := []string{InvTag, vpcID}
	zone = strings.TrimSpace(zone)

	zoneIdentity := vpcv1.ZoneIdentity{Name: &zone}
	vpcIdentity := vpcv1.VPCIdentityByID{ID: &vpcID}
	subnetName := GenerateResourceName(subnetType)

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

	err = c.attachTag(subnet.CRN, subnetTags)
	if err != nil {
		utils.Log.Print("Failed to tag subnet with error:", err)
		return nil, err
	}

	// TODO If required, attach the subnet to a gateway:
	// 1. if a public gateway doesn't already exist in the zone, create it.
	// 2. attach subnet to gateway.
	return subnet, nil
}

// GetSubnetsInVPC returns all subnets in vpc, user's and invisinets'.
func (c *CloudClient) GetSubnetsInVPC(vpcID string) ([]vpcv1.Subnet, error) {
	subnetOptions := &vpcv1.ListSubnetsOptions{VPCID: &vpcID}
	utils.Log.Printf("Getting subnets for vpc : %s", vpcID)
	subnets, resp, err := c.vpcService.ListSubnets(subnetOptions)
	if err != nil {
		utils.Log.Printf("%s", resp)
		return nil, err
	}
	utils.Log.Printf("subnets: %+v", subnets)
	return subnets.Subnets, nil
}

// DeleteSubnets deletes all subnets in the specified VPC.
func (c *CloudClient) DeleteSubnets(vpcID string) error {
	subnets, err := c.GetSubnetsInVPC(vpcID)
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
func (c *CloudClient) GetSubnetCIDR(subnetID string) (string, error) {
	subnet, _, err := c.vpcService.GetSubnet(c.vpcService.NewGetSubnetOptions(subnetID))
	if err != nil {
		return "", err
	}
	return *subnet.Ipv4CIDRBlock, nil
}
