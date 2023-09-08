package ibm

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/globalsearchv2"
	"github.com/IBM/platform-services-go-sdk/globaltaggingv1"
	"github.com/IBM/vpc-go-sdk/vpcv1"
)

type InstanceProfile string

const (
	credentialsPath   string          = ".ibm/credentials.yaml"
	publicSSHKey                      = ".ibm/keys/invisinets-key.pub"
	privateSSHKey                     = ".ibm/keys/invisinets-key"
	defaultImage                      = "ibm-ubuntu-22-04"
	imageArchitecture                 = "amd64"
	ResourcePrefix                    = "invisinets"
	LowCPU            InstanceProfile = "bx2-2x8"
	HighCPU           InstanceProfile = "bx2-8x32"
	GPU               InstanceProfile = "gx2-8x64x1v100"
)

type IBMCloudClient struct {
	vpcService     *vpcv1.VpcV1
	region         string // region resources will be created in/fetched from
	globalSearch   *globalsearchv2.GlobalSearchV2
	taggingService *globaltaggingv1.GlobalTaggingV1
	resourceGroup  *vpcv1.ResourceGroupIdentityByID
}

// updates the vpc service's url service to the specified region
func (c *IBMCloudClient) UpdateRegion(region string) {
	c.region = region
	c.vpcService.SetServiceURL(endpointURL(region))
}

func NewIbmCloudClient(region string) (*IBMCloudClient, error) {
	creds := get_ibm_cred()
	apiKey, resourceGroupID := creds[0], creds[1]
	authenticator := &core.IamAuthenticator{ApiKey: apiKey}
	options := vpcv1.VpcV1Options{
		Authenticator: authenticator,
		URL:           endpointURL(region),
	}
	api, err := vpcv1.NewVpcV1(&options)
	if err != nil {
		log.Println("Failed to create vpc service client with error:\n", err)
		return nil, err
	}

	globalSearch, err := globalsearchv2.NewGlobalSearchV2(&globalsearchv2.GlobalSearchV2Options{
		Authenticator: authenticator,
	})
	if err != nil {
		log.Println("Failed to create global search client with error:\n", err)
		return nil, err
	}

	taggingService, err := globaltaggingv1.NewGlobalTaggingV1(&globaltaggingv1.GlobalTaggingV1Options{
		Authenticator: authenticator,
	})
	if err != nil {
		log.Println("Failed to create tagging client with error:\n", err)
		return nil, err
	}

	resourceGroupIdentity := &vpcv1.ResourceGroupIdentityByID{ID: &resourceGroupID}

	client := IBMCloudClient{
		vpcService:     api,
		region:         region,
		globalSearch:   globalSearch,
		taggingService: taggingService,
		resourceGroup:  resourceGroupIdentity,
	}
	return &client, nil
}

func (c *IBMCloudClient) CreateVpc(vpcName string) (*vpcv1.VPC, error) {
	vpcTags := []string{ResourcePrefix}
	if vpcName == "" {
		vpcName = GenerateResourceName("vpc")
	}

	options := vpcv1.CreateVPCOptions{
		Name:          &vpcName,
		ResourceGroup: c.resourceGroup,
	}

	vpc, response, err := c.vpcService.CreateVPC(&options)
	if err != nil {
		log.Println("Failed to create VPC with error:", err,
			"\nResponse:\n", response)
		return nil, err
	}

	err = c.attachTagVPC(vpc.CRN, vpcTags)
	if err != nil {
		log.Print("Failed to tag VPC with error:", err)
		return nil, err
	}
	log.Printf("Created VPC:%v with ID:%v", *vpc.Name, *vpc.ID)
	return vpc, nil
}

func (c *IBMCloudClient) attachTagVPC(vpcCRN *string, tags []string) error {
	userTypeTag := globaltaggingv1.AttachTagOptionsTagTypeUserConst
	resourceModel := &globaltaggingv1.Resource{
		ResourceID:   vpcCRN,
		ResourceType: &userTypeTag,
	}
	attachTagOptions := c.taggingService.NewAttachTagOptions(
		[]globaltaggingv1.Resource{*resourceModel},
	)
	attachTagOptions = attachTagOptions.SetTagNames(tags)
	_, response, err := c.taggingService.AttachTag(attachTagOptions)
	if err != nil {
		log.Println("failed to tag VPC.\nResponse:", response, "\nError:\n", err)
		return err
	}
	return nil
}

func (c *IBMCloudClient) GetVpcByID(vpcID string) (*vpcv1.VPC, error) {
	vpc, response, err := c.vpcService.GetVPC(&vpcv1.GetVPCOptions{
		ID: &vpcID,
	})
	if err != nil {
		log.Println("Failed to retrieve VPC.\n Error:", err, "\nResponse\n", response)
		return nil, err
	}
	return vpc, nil
}

func (c *IBMCloudClient) GetVpcByTags(tags []string) ([]*vpcv1.VPC, error) {
	var tagsQueryFormat string
	var taggedVpcList []*vpcv1.VPC
	for _, tag := range tags {
		tagsQueryFormat += tag + ","
	}
	tagsQueryFormat = tagsQueryFormat[:len(tagsQueryFormat)-1] // remove last comma

	tagsStr := fmt.Sprintf("type:vpc AND tags:%v AND region:%v", tagsQueryFormat, c.Region())
	// tagsStr := fmt.Sprintf("type:vpc AND tags:%v AND region:us-south", tagsQueryFormat)

	searchOptions := c.globalSearch.NewSearchOptions()
	searchOptions.SetLimit(100)
	searchOptions.SetQuery(tagsStr)
	searchOptions.SetFields([]string{"tags", "region", "type"})

	result, response, err := c.globalSearch.Search(searchOptions)
	if err != nil {
		log.Println("tags search was invalid. Response\n", response)
		return nil, err
	}
	items := result.Items
	if len(items) != 0 {
		for _, item := range items {
			vpcID := CRN2ID(*item.CRN)
			vpc, err := c.GetVpcByID(vpcID)
			if err != nil {
				log.Println("Failed to locate VPC queried by tags")
				return nil, err
			}
			taggedVpcList = append(taggedVpcList, vpc)
		}
	} else { // no VPCs are tagged with query
		return nil, nil
	}
	return taggedVpcList, nil
}

// Creates a subnet in the zone and specified VPC.
// if zone not specified, a subnet will be created on random
// allocated address space allocated for the VPC.
func (c *IBMCloudClient) CreateSubnet(
	vpcID, zone, addressSpace string,
) (*vpcv1.Subnet, error) {

	var cidrBlock *string
	zone = strings.TrimSpace(zone)
	listVpcAddressPrefixesOptions := &vpcv1.ListVPCAddressPrefixesOptions{
		VPCID: &vpcID,
	}
	addressPrefixes, _, err :=
		c.vpcService.ListVPCAddressPrefixes(listVpcAddressPrefixesOptions)
	if err != nil {
		log.Println("No address prefixes were found in vpc: ", vpcID,
			"with error:\n", err)
		return nil, err
	}

	if addressSpace != "" {
		for _, addressPrefix := range addressPrefixes.AddressPrefixes {
			doesAddressFinInVPC, err := IsCidrSubset(addressSpace, *addressPrefix.CIDR)
			if err != nil {
				log.Printf("Address space specified: %v isn't formatted correctly",
					addressSpace)
				return nil, err
			}
			if doesAddressFinInVPC {
				// before picking an CIDR block verify that it does not overlap with the vpc's subnets
				doesOverlap, err := c.DoSubnetsInVpcOverlapCIDR(vpcID, addressSpace)
				if err != nil {
					return nil, err
				}
				if !doesOverlap {
					if zone == "" {
						cidrBlock = &addressSpace
						zone = *addressPrefix.Zone.Name
					} else if zone == *addressPrefix.Zone.Name {
						cidrBlock = &addressSpace
					}
				}
			}
			if cidrBlock != nil {
				// for optimization, exit when a CIDR block was chosen
				break
			}
		}
	} else {
		// if zone was specified, a CIDR in that zone is chosen,
		// otherwise a random CIDR is chosen and its zone is set.
		for _, addressPrefix := range addressPrefixes.AddressPrefixes {
			// choose a random cidr out of current vpc address prefix
			vpcAddressPrefix := *addressPrefix.CIDR
			cidrParts := strings.Split(vpcAddressPrefix, "/")
			//modify network mask to hold 256 ips if needed
			if maskPrefix, _ := strconv.Atoi(cidrParts[1]); maskPrefix < 24 {
				cidrParts[1] = "24"
			}
			randomCidr := strings.Join(cidrParts, "/")

			// before picking an CIDR block verify that it does not overlap with the vpc's subnets
			doesOverlap, err := c.DoSubnetsInVpcOverlapCIDR(vpcID, randomCidr)
			if err != nil {
				return nil, err
			}
			// if subnet doesn't no overlap
			if !doesOverlap {
				if zone == "" {
					cidrBlock = &randomCidr
					zone = *addressPrefix.Zone.Name
				} else if *addressPrefix.Zone.Name == zone {
					cidrBlock = &randomCidr
				}

				if cidrBlock != nil {
					// for optimization, exit when a CIDR block was chosen
					break
				}
			}
		}
	}
	if *cidrBlock == "" {
		log.Println("Failed to locate CIDR block for subnet")
		return nil, fmt.Errorf("failed to locate CIDR block for subnet")
	}

	zoneIdentity := vpcv1.ZoneIdentity{Name: &zone}
	vpcIdentity := vpcv1.VPCIdentityByID{ID: &vpcID}

	subnetPrototype := vpcv1.SubnetPrototype{
		Zone:          &zoneIdentity,
		Ipv4CIDRBlock: cidrBlock,
		VPC:           &vpcIdentity,
		ResourceGroup: c.resourceGroup,
	}
	options := vpcv1.CreateSubnetOptions{SubnetPrototype: &subnetPrototype}
	subnet, _, err := c.vpcService.CreateSubnet(&options)
	if err != nil {
		log.Println("Failed to create subnet with error:\n", err)
		return nil, err
	}

	// TODO If necessary, attach the subnet to a gateway:
	// 1. if a public gateway doesn't already exist in the zone, create it.
	// 2. attach the subnet to it to the above gateway.
	return subnet, nil
}

// return true if any of the specified vpc's subnets'
// cidr block overlap with given cidr
func (c *IBMCloudClient) DoSubnetsInVpcOverlapCIDR(vpcID string,
	CIDR string) (bool, error) {
	subnets, err := c.getSubnetsInVPC(vpcID)
	if err != nil {
		return true, err
	}

	for _, subnet := range subnets {
		doesOverlap, err := DoCidrOverlap(*subnet.Ipv4CIDRBlock, CIDR)
		if err != nil {
			return true, err
		}
		if doesOverlap {
			return true, nil
		}
	}
	return false, nil
}

func (c *IBMCloudClient) getSubnetsInVPC(vpcID string) ([]vpcv1.Subnet, error) {
	var subnetsList []vpcv1.Subnet
	routingTableCollection, _, err := c.vpcService.ListVPCRoutingTables(
		c.vpcService.NewListVPCRoutingTablesOptions(vpcID))
	if err != nil {
		return nil, err
	}
	// delete all subnets associated with given routing table
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

// creates ssh keys and registers them if absent.
// returns key id of registered public key.
func (c *IBMCloudClient) setupAuthentication() (string, error) {
	var publicKeyData, keyID string
	keyNameToRegister := GenerateResourceName("key")
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Println("Failed to generate home path: \n", err)
		return "", err
	}

	pubKeyPath := filepath.Join(homeDir, publicSSHKey)
	err = os.MkdirAll(filepath.Dir(filepath.Join(homeDir, publicSSHKey)), 0700)
	if err != nil {
		log.Println("Failed to create ssh key folder\n", err)
		return "", err
	}

	//check if ssh keys exist
	_, err = os.Stat(pubKeyPath)

	if err != nil {
		if os.IsNotExist(err) { // ssh keys do not exist
			data, keyGenErr := CreateSSHKeys(filepath.Join(homeDir, privateSSHKey))
			publicKeyData = data
			if keyGenErr != nil {
				log.Println("Failed to generate ssh keys.\nError:", keyGenErr)
				return "", err
			}
		} else { // Non expected error
			log.Println("Failed to verify if ssh keys exist", err)
			return "", err
		}
	} else { // ssh keys exist
		data, err := os.ReadFile(pubKeyPath)
		publicKeyData = string(data)
		if err != nil { // failed to read public ssh key data
			log.Println(err)
			return "", err
		}
	}

	// Register SSH key unless already registered
	result, _, err := c.vpcService.CreateKey(&vpcv1.CreateKeyOptions{
		Name:          &keyNameToRegister,
		PublicKey:     &publicKeyData,
		ResourceGroup: c.resourceGroup,
	})

	if err != nil {
		if strings.Contains(err.Error(), "fingerprint already exists") {
			log.Println("Reusing registered local SSH key")
			keyID, err = c.getKeyByPublicKey(publicKeyData)
			if err != nil {
				log.Println("Failed to reuse registered local SSH key")
				return "", err
			}
		} else {
			log.Println("Failed to register SSH key\n", err)
			return "", err
		}

	} else {
		keyID = *result.ID
	}
	return keyID, nil
}

func (c *IBMCloudClient) getKeyByPublicKey(publicKeyData string) (string, error) {
	var resultLimit int64 = 100 // number of results per API response
	publicKeyData = strings.TrimSpace(publicKeyData)
	listKeysOptions := &vpcv1.ListKeysOptions{Limit: &resultLimit}
	// TODO introduce pagination in case user has more then 100 keys in selected region

	keys, _, err := c.vpcService.ListKeys(listKeysOptions)
	if err != nil {
		log.Println(err)
		return "", nil
	}

	for _, key := range keys.Keys {
		if *key.PublicKey == publicKeyData {
			log.Println("Found matching registered key:", *key.ID)
			return *key.ID, nil
		}
	}
	return "", fmt.Errorf(`no registered key matching the specified public
			 key was found`)
}

// return image ID of default image
func (c *IBMCloudClient) getDefaultImageID() (imageID string, err error) {
	result, _, err := c.vpcService.ListImages(&vpcv1.ListImagesOptions{})
	if err != nil {
		log.Println("Failed to fetch VPC image collection with the",
			"following error:\n", err)
		return "", err
	}
	for _, image := range result.Images {
		if strings.HasPrefix(*image.Name, defaultImage) &&
			*image.OperatingSystem.Architecture == imageArchitecture {
			return *image.ID, nil
		}
	}
	log.Println("Failed to retrieve image named by prefix: ", defaultImage)
	return "", nil
}

// returns subnets in the specified zone, in the specified VPC
// if getOneSubnet is set to true, returns a single subnet
func (c *IBMCloudClient) getSubnetsInZone(zone string, vpcID string,
	getOneSubnet bool) ([]string, error) {
	var subnetIDs []string
	options := &vpcv1.ListSubnetsOptions{}
	subnets, _, err := c.vpcService.ListSubnets(options)
	if err != nil {
		log.Println("Failed to retrieve subnets")
		return nil, err
	}
	for _, subnet := range subnets.Subnets {
		subnetID := *subnet.VPC.ID
		if *subnet.VPC.ID == vpcID && *subnet.Zone.Name == zone {
			subnetIDs = append(subnetIDs, subnetID)
			if getOneSubnet {
				break
			}
		}
	}
	return subnetIDs, nil
}

// creates VM in a the specified subnet and zone.
// if subnet id isn't specified, the VM will be created
// on a random subnet in the selected zone.
func (c *IBMCloudClient) CreateDefaultVM(vpcID, subnetID,
	zone, name, profile string) (*vpcv1.Instance, error) {
	keyID, err := c.setupAuthentication()
	if err != nil {
		log.Println("failed to setup authentication")
		return nil, err
	}
	if profile == "" {
		profile = string(LowCPU)
	}
	imageID, err := c.getDefaultImageID()
	if imageID == "" || err != nil {
		log.Println("Failed to retrieve default image")
		return nil, err
	}
	if err != nil {
		log.Println("Failed to set up IBM",
			"authentication with error: ", err)
		return nil, err
	}
	// pick a random subnet if non was provided
	if subnetID == "" {
		subnetIDs, err := c.getSubnetsInZone(zone, vpcID, true)
		if err != nil || len(subnetIDs) == 0 {
			log.Println("Failed to create VM. No subnets found in ", zone)
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
		log.Println("Failed to create security group for VM with error: ", err)
		return nil, err
	}

	sgGrps := []vpcv1.SecurityGroupIdentityIntf{
		&vpcv1.SecurityGroupIdentityByID{ID: securityGroup.ID}}

	instance, err := c.CreateVM(imageID, profile, keyID, vpcID,
		subnetID, zone, name, sgGrps)
	if err != nil {
		log.Println("Failed to launch instance with error:\n", err)
		return nil, err
	}
	return instance, nil

}

func (c *IBMCloudClient) CreateVM(
	imageID, profile, keyID, vpcID, subnetID, zone, name string,
	securityGroups []vpcv1.SecurityGroupIdentityIntf) (
	*vpcv1.Instance, error) {

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
	return instance, nil

}

func (c *IBMCloudClient) createSecurityGroup(
	vpcID string) (*vpcv1.SecurityGroup, error) {

	vpcIdentity := vpcv1.VPCIdentityByID{ID: &vpcID}
	options := vpcv1.CreateSecurityGroupOptions{
		VPC:           &vpcIdentity,
		ResourceGroup: c.resourceGroup,
	}
	sg, _, err := c.vpcService.CreateSecurityGroup(&options)
	if err != nil {
		return nil, err
	}
	return sg, nil
}

func (c *IBMCloudClient) Region() string {
	return c.region
}

// deletes floating ips marked recyclable, that are attached to
// any interface associated with given VM
func (c *IBMCloudClient) DeleteFloatingIPsOfVM(vm *vpcv1.Instance) {
	recyclableResource := "recyclable"

	for _, nic := range vm.NetworkInterfaces {
		options := c.vpcService.NewListInstanceNetworkInterfaceFloatingIpsOptions(*vm.ID, *nic.ID)
		ips, _, err := c.vpcService.ListInstanceNetworkInterfaceFloatingIps(options)
		if err != nil {
			log.Println(err)
		}
		for _, ip := range ips.FloatingIps {
			if strings.Contains(recyclableResource, *ip.Name) {
				_, err := c.vpcService.DeleteFloatingIP(c.vpcService.NewDeleteFloatingIPOptions(*ip.ID))
				if err != nil {
					log.Println(err)
				}
				log.Println("Deleted recyclable IP: ", *ip.Address)
			}
		}
	}
}

func (c *IBMCloudClient) DeleteSubnets(vpcID string) error {
	subnets, err := c.getSubnetsInVPC(vpcID)
	if err != nil {
		return err
	}
	for _, subnet := range subnets {
		options := &vpcv1.DeleteSubnetOptions{ID: subnet.ID}
		_, err := c.vpcService.DeleteSubnet(options)
		if err != nil {
			log.Printf("Failed to delete subnet %v with error:%v",
				subnet.ID, err)
			return err
		}
	}
	return nil
}

func (c *IBMCloudClient) TerminateVPC(vpcID string) error {

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
		c.DeleteFloatingIPsOfVM(&instance)
		// delete current VM
		_, err := c.vpcService.DeleteInstance(
			&vpcv1.DeleteInstanceOptions{ID: instance.ID})
		if err != nil {
			return err
		}
	}
	//wait for instances deletion process to end
	for _, instance := range instanceList.Instances {
		if !c.poll_instance_exist(*instance.ID) {
			return fmt.Errorf("failed to remove instance within the alloted time frame")
		}
	}

	err = c.DeleteSubnets(vpcID)
	if err != nil {
		return err
	}

	// Delete the VPC
	_, err = c.vpcService.DeleteVPC(&vpcv1.DeleteVPCOptions{
		ID: &vpcID,
	})
	if err != nil {
		return err
	}

	log.Printf("VPC %v deleted successfully", vpcID)
	return nil
}

// returns VPC id of specified vm
func (c *IBMCloudClient) VmID2VpcID(vmID string) string {
	instance, _, err := c.vpcService.GetInstance(
		&vpcv1.GetInstanceOptions{ID: &vmID})
	if err != nil {
		log.Fatal(err)
	}
	return *instance.VPC.ID
}

// returns true when instance was completely removed from the subnet
// returns false if failed to remove instance within the alloted time frame
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
