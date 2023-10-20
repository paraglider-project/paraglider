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
	"strings"

	"github.com/IBM/vpc-go-sdk/vpcv1"

	utils "github.com/NetSys/invisinets/pkg/utils"
)

// CreateSubnet creates subnet in specified vpc and zone.
// tag subnet with invisinets prefix and vpc ID.
func (c *CloudClient) CreateSubnet(
	vpcID, zone, addressSpace string) (*vpcv1.Subnet, error) {
	var cidrBlock *string
	subnetTags := []string{vpcID}
	zone = strings.TrimSpace(zone)
	listVpcAddressPrefixesOptions := &vpcv1.ListVPCAddressPrefixesOptions{
		VPCID: &vpcID,
	}

	addressPrefixes, _, err :=
		c.vpcService.ListVPCAddressPrefixes(listVpcAddressPrefixesOptions)
	if err != nil {
		utils.Log.Println("No address prefixes were found in vpc: ", vpcID,
			"with error:\n", err)
		return nil, err
	}

	for _, addressPrefix := range addressPrefixes.AddressPrefixes {
		if zone == *addressPrefix.Zone.Name {
			if addressSpace == "" {
				cidrBlock = addressPrefix.CIDR
			} else {
				doesAddressFitInVPC, err := IsCIDRSubset(addressSpace, *addressPrefix.CIDR)
				if err != nil {
					return nil, err
				}
				if doesAddressFitInVPC {
					// before picking a CIDR block verify that it does not overlap with the vpc's subnets
					doesOverlap, err := c.DoSubnetsInVPCOverlapCIDR(vpcID, addressSpace)
					if err != nil {
						return nil, err
					}
					if !doesOverlap {
						cidrBlock = &addressSpace
					}
				}
			}

			if cidrBlock != nil {
				// Optimize by exiting when a CIDR block was chosen
				break
			}
		}
	}

	if cidrBlock == nil {
		utils.Log.Println("Failed to locate CIDR block for subnet")
		return nil, fmt.Errorf("failed to locate CIDR block for subnet")
	}

	zoneIdentity := vpcv1.ZoneIdentity{Name: &zone}
	vpcIdentity := vpcv1.VPCIdentityByID{ID: &vpcID}
	subnetName := GenerateResourceName("subnet")

	subnetPrototype := vpcv1.SubnetPrototype{
		Zone:          &zoneIdentity,
		Ipv4CIDRBlock: cidrBlock,
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
	var subnetsList []vpcv1.Subnet
	routingTableCollection, _, err := c.vpcService.ListVPCRoutingTables(
		c.vpcService.NewListVPCRoutingTablesOptions(vpcID))
	if err != nil {
		return nil, err
	}
	// get all subnets associated with given routing table
	for _, routingTable := range routingTableCollection.RoutingTables {
		options := &vpcv1.ListSubnetsOptions{
			RoutingTableID:  routingTable.ID,
			ResourceGroupID: c.resourceGroup.ID}
		subnets, _, err := c.vpcService.ListSubnets(options)
		if err != nil {
			return nil, err
		}
		subnetsList = append(subnetsList, subnets.Subnets...)
	}
	return subnetsList, nil
}

// DoSubnetsInVPCOverlapCIDR returns true if any of the specified vpc's subnets'
// address space overlap with given cidr
func (c *CloudClient) DoSubnetsInVPCOverlapCIDR(vpcID string,
	CIDR string) (bool, error) {
	subnets, err := c.GetSubnetsInVPC(vpcID)
	if err != nil {
		return true, err
	}

	for _, subnet := range subnets {
		doesOverlap, err := DoCIDROverlap(*subnet.Ipv4CIDRBlock, CIDR)
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
