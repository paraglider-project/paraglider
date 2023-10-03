package ibm

import (
	"fmt"
	"strings"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/globalsearchv2"
	"github.com/IBM/platform-services-go-sdk/globaltaggingv1"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	logger "github.com/NetSys/invisinets/pkg/logger"
)

type IBMCloudClient struct {
	vpcService     *vpcv1.VpcV1
	region         string // region resources will be created in/fetched from
	globalSearch   *globalsearchv2.GlobalSearchV2
	taggingService *globaltaggingv1.GlobalTaggingV1
	resourceGroup  *vpcv1.ResourceGroupIdentityByID
}

func (c *IBMCloudClient) Region() string {
	return c.region
}

// updates the vpc service's url service to the specified region
func (c *IBMCloudClient) UpdateRegion(region string) {
	c.region = region
	c.vpcService.SetServiceURL(endpointURL(region))
}

func NewIbmCloudClient(region string) (*IBMCloudClient, error) {
	creds, err := get_ibm_cred()
	if err != nil {
		return nil, err
	}
	apiKey, resourceGroupID := creds.APIKey, creds.ResourceGroupID
	authenticator := &core.IamAuthenticator{ApiKey: apiKey}
	options := vpcv1.VpcV1Options{
		Authenticator: authenticator,
		URL:           endpointURL(region),
	}
	api, err := vpcv1.NewVpcV1(&options)
	if err != nil {
		logger.Log.Println("Failed to create vpc service client with error:\n", err)
		return nil, err
	}

	globalSearch, err := globalsearchv2.NewGlobalSearchV2(&globalsearchv2.GlobalSearchV2Options{
		Authenticator: authenticator,
	})
	if err != nil {
		logger.Log.Println("Failed to create global search client with error:\n", err)
		return nil, err
	}

	taggingService, err := globaltaggingv1.NewGlobalTaggingV1(&globaltaggingv1.GlobalTaggingV1Options{
		Authenticator: authenticator,
	})
	if err != nil {
		logger.Log.Println("Failed to create tagging client with error:\n", err)
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

// creates a vpc and a subnet in each zone. resources are tagged.
// if cidrBlock isn't specified, auto-generated address prefixes for the zones are chosen,
// other wise the vpc's zones will span over it.
func (c *IBMCloudClient) CreateVpc(vpcName string, cidrBlock string) (*vpcv1.VPC, error) {
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
		logger.Log.Println("Failed to create VPC with error:", err,
			"\nResponse:\n", response)
		return nil, err
	}

	if cidrBlock != "" {
		//split the provided cidr block 3-ways and create 3 address prefixes.
		addressPrefixes, err = SplitCidr3Ways(cidrBlock)
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
				logger.Log.Println("Failed to create subnet with error:",
					err)
				return nil, err
			}

		}

	}
	err = c.attachTag(vpc.CRN, vpcTags)
	if err != nil {
		logger.Log.Print("Failed to tag VPC with error:", err)
		return nil, err
	}
	logger.Log.Printf("Created VPC:%v with ID:%v", *vpc.Name, *vpc.ID)
	return vpc, nil
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
	// wait for instances deletion process to end
	for _, instance := range instanceList.Instances {
		if !c.poll_instance_exist(*instance.ID) {
			return fmt.Errorf("failed to remove instance within the alloted time frame")
		}
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

	logger.Log.Printf("VPC %v deleted successfully", vpcID)
	return nil
}

func (c *IBMCloudClient) GetVpcByID(vpcID string) (*vpcv1.VPC, error) {
	vpc, response, err := c.vpcService.GetVPC(&vpcv1.GetVPCOptions{
		ID: &vpcID,
	})
	if err != nil {
		logger.Log.Println("Failed to retrieve VPC.\n Error:", err, "\nResponse\n", response)
		return nil, err
	}
	return vpc, nil
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

// create subnet in specified vpc and zone.
// tag subnet with invisinets prefix and vpc ID.
func (c *IBMCloudClient) CreateSubnet(
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
		logger.Log.Println("No address prefixes were found in vpc: ", vpcID,
			"with error:\n", err)
		return nil, err
	}

	for _, addressPrefix := range addressPrefixes.AddressPrefixes {
		if zone == *addressPrefix.Zone.Name {
			if addressSpace == "" {
				cidrBlock = addressPrefix.CIDR
			} else {
				doesAddressFitInVPC, err := IsCidrSubset(addressSpace, *addressPrefix.CIDR)
				if err != nil {
					return nil, err
				}
				if doesAddressFitInVPC {
					// before picking a CIDR block verify that it does not overlap with the vpc's subnets
					doesOverlap, err := c.DoSubnetsInVpcOverlapCIDR(vpcID, addressSpace)
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
		logger.Log.Println("Failed to locate CIDR block for subnet")
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
		logger.Log.Println("Failed to create subnet with error:\n", err)
		return nil, err
	}
	logger.Log.Printf("Created subnet %v with id %v", subnetName, *subnet.ID)

	err = c.attachTag(subnet.CRN, subnetTags)
	if err != nil {
		logger.Log.Print("Failed to tag subnet with error:", err)
		return nil, err
	}

	// TODO If required, attach the subnet to a gateway:
	// 1. if a public gateway doesn't already exist in the zone, create it.
	// 2. attach subnet to gateway.
	return subnet, nil
}

// returns all subnets in vpc, user's and invisinets'.
func (c *IBMCloudClient) GetSubnetsInVPC(vpcID string) ([]vpcv1.Subnet, error) {
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

// return true if any of the specified vpc's subnets'
// address space overlap with given cidr
func (c *IBMCloudClient) DoSubnetsInVpcOverlapCIDR(vpcID string,
	CIDR string) (bool, error) {
	subnets, err := c.GetSubnetsInVPC(vpcID)
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

// deletes all subnets in the specified VPC.
func (c *IBMCloudClient) DeleteSubnets(vpcID string) error {
	subnets, err := c.GetSubnetsInVPC(vpcID)
	if err != nil {
		return err
	}
	for _, subnet := range subnets {
		options := &vpcv1.DeleteSubnetOptions{ID: subnet.ID}
		_, err := c.vpcService.DeleteSubnet(options)
		if err != nil {
			logger.Log.Printf("Failed to delete subnet %v with error:%v",
				subnet.ID, err)
			return err
		}
	}
	return nil
}

// creates ssh keys and registers them if absent.
// returns key id of registered public key.
func (c *IBMCloudClient) setupAuthentication() (string, error) {
	var keyID string
	keyNameToRegister := GenerateResourceName("key")

	publicKeyData, err := getLocalPubKey()
	if err != nil {
		return "", err
	}
	if publicKeyData == "" {
		return "", fmt.Errorf("empty data returned for public key")
	}
	// Register SSH key unless already registered
	result, _, err := c.vpcService.CreateKey(&vpcv1.CreateKeyOptions{
		Name:          &keyNameToRegister,
		PublicKey:     &publicKeyData,
		ResourceGroup: c.resourceGroup,
	})

	if err != nil {
		if strings.Contains(err.Error(), "fingerprint already exists") {
			logger.Log.Println("Reusing registered local SSH key")
			keyID, err = c.getKeyByPublicKey(publicKeyData)
			if err != nil {
				logger.Log.Println("Failed to reuse registered local SSH key")
				return "", err
			}
		} else {
			logger.Log.Println("Failed to register SSH key\n", err)
			return "", err
		}

	} else {
		keyID = *result.ID
	}
	return keyID, nil
}

// returns key id of a registered key matching the public key data.
func (c *IBMCloudClient) getKeyByPublicKey(publicKeyData string) (string, error) {
	var resultLimit int64 = 100 // number of results per API response
	publicKeyData = strings.TrimSpace(publicKeyData)
	listKeysOptions := &vpcv1.ListKeysOptions{Limit: &resultLimit}
	// TODO introduce pagination in case user has more then 100 keys in selected region

	keys, _, err := c.vpcService.ListKeys(listKeysOptions)
	if err != nil {
		logger.Log.Println(err)
		return "", nil
	}

	for _, key := range keys.Keys {
		if *key.PublicKey == publicKeyData {
			logger.Log.Println("Found matching registered key:", *key.ID)
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
		logger.Log.Println("Failed to fetch VPC image collection with the",
			"following error:\n", err)
		return "", err
	}
	for _, image := range result.Images {
		if strings.HasPrefix(*image.Name, defaultImage) &&
			*image.OperatingSystem.Architecture == imageArchitecture {
			return *image.ID, nil
		}
	}
	logger.Log.Println("Failed to retrieve image named by prefix: ", defaultImage)
	return "", nil
}

// creates VM in a the specified subnet and zone.
// if subnet id isn't specified, the VM will be created
// on a random subnet in the selected zone.
func (c *IBMCloudClient) CreateVM(vpcID, subnetID,
	zone, name, profile string) (*vpcv1.Instance, error) {
	keyID, err := c.setupAuthentication()
	if err != nil {
		logger.Log.Println("failed to setup authentication")
		return nil, err
	}
	if profile == "" {
		profile = string(LowCPU)
	}
	imageID, err := c.getDefaultImageID()
	if imageID == "" || err != nil {
		logger.Log.Println("Failed to retrieve default image")
		return nil, err
	}
	if err != nil {
		logger.Log.Println("Failed to set up IBM",
			"authentication with error: ", err)
		return nil, err
	}
	// pick a subnet if non was provided
	if subnetID == "" {
		subnetIDs, err := c.GetInvisinetsTaggedResources(SUBNET, []string{vpcID}, ResourceQuery{Zone: zone})
		if err != nil || len(subnetIDs) == 0 {
			logger.Log.Println("Failed to create VM. No subnets found in ", zone)
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
		logger.Log.Println("Failed to create security group for VM with error: ", err)
		return nil, err
	}

	sgGrps := []vpcv1.SecurityGroupIdentityIntf{
		&vpcv1.SecurityGroupIdentityByID{ID: securityGroup.ID}}

	instance, err := c.createVM(imageID, profile, keyID, vpcID,
		subnetID, zone, name, sgGrps)
	if err != nil {
		logger.Log.Println("Failed to launch instance with error:\n", err)
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
	logger.Log.Printf("VM %v was launched with ID: %v", name, *instance.ID)

	err = c.attachTag(instance.CRN, instanceTags)
	if err != nil {
		logger.Log.Print("Failed to tag VPC with error:", err)
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

// deletes floating ips marked recyclable, that are attached to
// any interface associated with given VM
func (c *IBMCloudClient) DeleteFloatingIPsOfVM(vm *vpcv1.Instance) {
	recyclableResource := "recyclable"

	for _, nic := range vm.NetworkInterfaces {
		options := c.vpcService.NewListInstanceNetworkInterfaceFloatingIpsOptions(*vm.ID, *nic.ID)
		ips, _, err := c.vpcService.ListInstanceNetworkInterfaceFloatingIps(options)
		if err != nil {
			logger.Log.Println(err)
		}
		for _, ip := range ips.FloatingIps {
			if strings.Contains(recyclableResource, *ip.Name) {
				_, err := c.vpcService.DeleteFloatingIP(c.vpcService.NewDeleteFloatingIPOptions(*ip.ID))
				if err != nil {
					logger.Log.Println(err)
				}
				logger.Log.Println("Deleted recyclable IP: ", *ip.Address)
			}
		}
	}
}

// creates security group in the specified VPC and tags it.
func (c *IBMCloudClient) createSecurityGroup(
	vpcID string) (*vpcv1.SecurityGroup, error) {
	sgTags := []string{vpcID}

	vpcIdentity := vpcv1.VPCIdentityByID{ID: &vpcID}
	sgName := GenerateResourceName("sg")
	options := vpcv1.CreateSecurityGroupOptions{
		VPC:           &vpcIdentity,
		ResourceGroup: c.resourceGroup,
		Name:          &sgName,
	}
	sg, _, err := c.vpcService.CreateSecurityGroup(&options)
	if err != nil {
		return nil, err
	}
	logger.Log.Printf("Created security group %v with id %v", sgName, *sg.ID)

	err = c.attachTag(sg.CRN, sgTags)
	if err != nil {
		logger.Log.Print("Failed to tag VPC with error:", err)
		return nil, err
	}
	return sg, nil
}

func (c *IBMCloudClient) GetSecurityRulesOfSG(sgID string) ([]SecurityGroupRule, error) {
	options := &vpcv1.ListSecurityGroupRulesOptions{}
	options.SetSecurityGroupID(sgID)
	rules, _, err := c.vpcService.ListSecurityGroupRules(options)
	if err != nil {
		return nil, err
	}
	return c.translateSecurityGroupRules(rules.Rules, &sgID)
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

func (c *IBMCloudClient) attachTag(CRN *string, tags []string) error {
	tags = append(tags, ResourcePrefix)
	userTypeTag := globaltaggingv1.AttachTagOptionsTagTypeUserConst
	resourceModel := &globaltaggingv1.Resource{
		ResourceID:   CRN,
		ResourceType: &userTypeTag,
	}
	attachTagOptions := c.taggingService.NewAttachTagOptions(
		[]globaltaggingv1.Resource{*resourceModel},
	)
	attachTagOptions = attachTagOptions.SetTagNames(tags)
	_, _, err := c.taggingService.AttachTag(attachTagOptions)
	if err != nil {
		return err
	}
	return nil
}

// returns slice of IDs of tagged resources
// Arg resourceType: type of VPC resource, e.g. subnet, security group, instance.
// Arg tags: labels set by dev, e.g. {<vpcID>,<deploymentID>}
// Args customQueryMap: map of attributes to filter by, e.g. {"region":"<regionName>"}
func (c *IBMCloudClient) GetInvisinetsTaggedResources(resourceType TaggedResourceType, tags []string,
	customQuery ResourceQuery) ([]string, error) {
	// parse tags
	var tagsStr string
	var queryStr string
	tags = append(tags, ResourcePrefix) // append the invisinets tag
	for _, tag := range tags {
		tagsStr += fmt.Sprintf("tags:%v AND ", tag)
	}
	tagsStr = strings.TrimSuffix(tagsStr, "AND ") // remove last operator

	// Parse region/zone individually to accommodate unique behavior:
	// globalSearch returns the region field for all resources, although for some it holds
	// the zone value, e.g. subnet's region actually contain a zone's value.
	if customQuery.Zone != "" {
		queryStr += fmt.Sprintf("%v:%v ", "region", customQuery.Zone)
	} else if customQuery.Region != "" {
		queryStr += fmt.Sprintf("%v:%v* ", "region", customQuery.Region)
		// e.g. region:eu-de* would fetch all zones in eu-de for zone bound resources
	}

	resourceList, err := c.getInvisinetsResourceByTags(string(resourceType), tagsStr, queryStr)
	if err != nil {
		return nil, err
	}
	return resourceList, nil
}

// returns IDs of resources filtered by tags and query
func (c *IBMCloudClient) getInvisinetsResourceByTags(resourceType string,
	tags string, customQueryStr string) ([]string, error) {
	var taggedResources []string

	query := fmt.Sprintf("type:%v AND %v ", resourceType, tags)
	if customQueryStr != "" {
		query += "AND " + customQueryStr
	}

	searchOptions := c.globalSearch.NewSearchOptions()
	searchOptions.SetLimit(100)
	searchOptions.SetQuery(query)
	searchOptions.SetFields([]string{"*"})

	result, response, err := c.globalSearch.Search(searchOptions)
	if err != nil {
		logger.Log.Println("tags search was invalid. Response\n", response)
		return nil, err
	}
	items := result.Items
	if len(items) != 0 {
		for _, item := range items {
			id := CRN2ID(*item.CRN)
			taggedResources = append(taggedResources, id)
		}
	} else { // no resources found with specified tags
		return nil, nil
	}
	return taggedResources, nil
}

/*
The following functions are responsible for transforming
the "vpcv1.SecurityGroupRuleIntf" interface to the SecurityGroupRule struct
*/

func (c *IBMCloudClient) translateSecurityGroupRules(
	ibmRules []vpcv1.SecurityGroupRuleIntf, sgID *string) ([]SecurityGroupRule, error) {

	rules := make([]SecurityGroupRule, len(ibmRules))
	for i, ibmRule := range ibmRules {
		rule, err := c.translateSecurityGroupRule(ibmRule, sgID)
		if err != nil {
			return nil, err
		} else {
			rules[i] = *rule
		}
	}
	return rules, nil
}

func (c *IBMCloudClient) translateSecurityGroupRule(
	ibmRule vpcv1.SecurityGroupRuleIntf, sgID *string) (*SecurityGroupRule, error) {
	switch ibmRule.(type) {
	case *vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolAll:
		return c.translateSecurityGroupRuleGroupRuleProtocolAll(ibmRule, sgID)
	case *vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp:
		return c.translateSecurityGroupRuleGroupRuleProtocolIcmp(ibmRule, sgID)
	case *vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp:
		return c.translateSecurityGroupRuleGroupRuleProtocolTcpudp(ibmRule, sgID)
	}
	return nil, nil
}

func (c *IBMCloudClient) translateSecurityGroupRuleGroupRuleProtocolAll(
	ibmRule vpcv1.SecurityGroupRuleIntf, sgID *string) (*SecurityGroupRule, error) {

	ibmRuleProtoAll := ibmRule.(*vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolAll)
	remote, remoteType, err := c.translateSecurityGroupRuleRemote(ibmRuleProtoAll.Remote)
	if err != nil {
		return nil, err
	}
	isEgress := false
	if *ibmRuleProtoAll.Direction == "outbound" {
		isEgress = true
	}
	rule := SecurityGroupRule{
		ID:         ibmRuleProtoAll.ID,
		Protocol:   ibmRuleProtoAll.Protocol,
		SgID:       sgID,
		Remote:     remote,
		RemoteType: remoteType,
		Egress:     &isEgress,
		PortMin:    core.Int64Ptr(int64(-1)),
		PortMax:    core.Int64Ptr(int64(-1)),
	}
	return &rule, nil
}

func (c *IBMCloudClient) translateSecurityGroupRuleGroupRuleProtocolIcmp(
	ibmRule vpcv1.SecurityGroupRuleIntf, sgID *string) (*SecurityGroupRule, error) {

	ibmRuleIcmp := ibmRule.(*vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp)
	remote, remoteType, err := c.translateSecurityGroupRuleRemote(ibmRuleIcmp.Remote)
	if err != nil {
		return nil, err
	}
	isEgress := false
	if *ibmRuleIcmp.Direction == "outbound" {
		isEgress = true
	}
	icmpCode := int64(-1)
	if ibmRuleIcmp.Code != nil {
		icmpCode = *ibmRuleIcmp.Code
	}
	icmpType := int64(-1)
	if ibmRuleIcmp.Type != nil {
		icmpType = *ibmRuleIcmp.Type
	}
	rule := SecurityGroupRule{
		ID:         ibmRuleIcmp.ID,
		Protocol:   ibmRuleIcmp.Protocol,
		SgID:       sgID,
		Remote:     remote,
		RemoteType: remoteType,
		IcmpCode:   &icmpCode,
		IcmpType:   &icmpType,
		Egress:     &isEgress,
	}
	return &rule, nil
}

func (c *IBMCloudClient) translateSecurityGroupRuleGroupRuleProtocolTcpudp(
	ibmRule vpcv1.SecurityGroupRuleIntf, sgID *string) (*SecurityGroupRule, error) {

	ibmRuleTcpUdp := ibmRule.(*vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp)
	remote, remoteType, err := c.translateSecurityGroupRuleRemote(ibmRuleTcpUdp.Remote)
	if err != nil {
		return nil, err
	}
	isEgress := false
	if *ibmRuleTcpUdp.Direction == "outbound" {
		isEgress = true
	}
	rule := SecurityGroupRule{
		ID:         ibmRuleTcpUdp.ID,
		Protocol:   ibmRuleTcpUdp.Protocol,
		SgID:       sgID,
		Remote:     remote,
		RemoteType: remoteType,
		PortMin:    ibmRuleTcpUdp.PortMin,
		PortMax:    ibmRuleTcpUdp.PortMax,
		Egress:     &isEgress,
	}
	return &rule, nil
}

func (c *IBMCloudClient) translateSecurityGroupRuleRemote(
	ibmRuleRemoteIntf vpcv1.SecurityGroupRuleRemoteIntf) (*string, *string, error) {

	switch v := ibmRuleRemoteIntf.(type) {
	// According to the docs, the interface should map to a specific type,
	// but in this case it seems to just map to a generic "remote" where pointers may be nil
	case *vpcv1.SecurityGroupRuleRemote:
		ibmRuleRemote := ibmRuleRemoteIntf.(*vpcv1.SecurityGroupRuleRemote)
		if ibmRuleRemote.Address != nil {
			return ibmRuleRemote.Address, core.StringPtr("IP"), nil
		}
		if ibmRuleRemote.CIDRBlock != nil {
			return ibmRuleRemote.CIDRBlock, core.StringPtr("CIDR"), nil
		}
		// For IBM Cloud, it is common to have an inbound rule accepting traffic
		// from a security group (sometimes the same where the rule belongs)
		if ibmRuleRemote.ID != nil {
			return ibmRuleRemote.ID, core.StringPtr("SG"), nil
		}
	default:
		return nil, nil, fmt.Errorf(
			"unexpected type for security group rule remote [%T]", v,
		)
	}
	return nil, nil, fmt.Errorf(
		"unexpected type for security group rule remote [%T]",
		ibmRuleRemoteIntf,
	)
}
