package ibm

import (
	"strings"
	"time"

	"github.com/IBM/vpc-go-sdk/vpcv1"
	utils "github.com/NetSys/invisinets/pkg/utils"
)

// creates VM in a the specified subnet and zone.
// if subnet id isn't specified, the VM will be created
// on a random subnet in the selected zone.
func (c *IBMCloudClient) CreateVM(vpcID, subnetID,
	zone, name, profile string) (*vpcv1.Instance, error) {
	keyID, err := c.setupAuthentication()
	if err != nil {
		utils.Log.Println("failed to setup authentication")
		return nil, err
	}
	if profile == "" {
		profile = string(LowCPU)
	}
	imageID, err := c.getDefaultImageID()
	if imageID == "" || err != nil {
		utils.Log.Println("Failed to retrieve default image")
		return nil, err
	}
	if err != nil {
		utils.Log.Println("Failed to set up IBM",
			"authentication with error: ", err)
		return nil, err
	}
	// pick a subnet if non was provided
	if subnetID == "" {
		subnetIDs, err := c.GetInvisinetsTaggedResources(SUBNET, []string{vpcID}, ResourceQuery{Zone: zone})
		if err != nil || len(subnetIDs) == 0 {
			utils.Log.Println("Failed to create VM. No subnets found in ", zone)
			return nil, err
		}
		subnetID = subnetIDs[0]
	}
	// generate a random VM name if non was provided
	if name == "" {
		name = GenerateResourceName("vm")
	}

	securityGroup, err := c.createSecurityGroup(vpcID)
	if err != nil {
		utils.Log.Println("Failed to create security group for VM with error: ", err)
		return nil, err
	}

	sgGrps := []vpcv1.SecurityGroupIdentityIntf{
		&vpcv1.SecurityGroupIdentityByID{ID: securityGroup.ID}}

	instance, err := c.createVM(imageID, profile, keyID, vpcID,
		subnetID, zone, name, sgGrps)
	if err != nil {
		utils.Log.Println("Failed to launch instance with error:\n", err)
		return nil, err
	}
	return instance, nil

}

func (c *IBMCloudClient) createVM(
	imageID, profile, keyID, vpcID, subnetID, zone, name string,
	securityGroups []vpcv1.SecurityGroupIdentityIntf) (
	*vpcv1.Instance, error) {
	instanceTags := []string{vpcID}

	subnetIdentity := vpcv1.SubnetIdentityByID{ID: &subnetID}

	nicPrototype := vpcv1.NetworkInterfacePrototype{
		Subnet:         &subnetIdentity,
		SecurityGroups: securityGroups,
	}
	keyIdentity := vpcv1.KeyIdentityByID{ID: &keyID}
	imageIdentity := vpcv1.ImageIdentityByID{ID: &imageID}
	zoneIdentity := vpcv1.ZoneIdentityByName{Name: &zone}
	prototype := vpcv1.InstancePrototypeInstanceByImage{
		Image:                   &imageIdentity,
		Keys:                    []vpcv1.KeyIdentityIntf{&keyIdentity},
		PrimaryNetworkInterface: &nicPrototype,
		Zone:                    &zoneIdentity,
		Name:                    &name,
		Profile:                 &vpcv1.InstanceProfileIdentityByName{Name: &profile},
		ResourceGroup:           c.resourceGroup,
	}
	options := vpcv1.CreateInstanceOptions{InstancePrototype: &prototype}
	instance, _, err := c.vpcService.CreateInstance(&options)
	if err != nil {
		return nil, err
	}
	utils.Log.Printf("VM %v was launched with ID: %v", name, *instance.ID)

	err = c.attachTag(instance.CRN, instanceTags)
	if err != nil {
		utils.Log.Print("Failed to tag VPC with error:", err)
		return nil, err
	}
	return instance, nil
}

// return security group ids that are associated with the VM's network interfaces
func (c *IBMCloudClient) GetSecurityGroupsOfVM(vmID string) ([]string, error) {
	var sgGroups []string
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
func (c *IBMCloudClient) deleteFloatingIPsOfVM(vm *vpcv1.Instance) {
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

// returns true when instance is completely removed from
// the subnet.
func (c *IBMCloudClient) poll_instance_exist(vmID string) bool {
	sleepDuration := 3 * time.Second
	for tries := 15; tries > 0; tries -= 1 {
		_, _, err := c.vpcService.GetInstance(c.vpcService.NewGetInstanceOptions(vmID))
		if err != nil {
			return true
		}
		time.Sleep(sleepDuration)
	}
	return false
}

// returns VPC id of specified instance
func (c *IBMCloudClient) VmID2VpcID(vmID string) (string, error) {
	instance, _, err := c.vpcService.GetInstance(
		&vpcv1.GetInstanceOptions{ID: &vmID})
	if err != nil {
		return "", err
	}
	return *instance.VPC.ID, nil
}
