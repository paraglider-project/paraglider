package ibm

import (
	"fmt"
	"strings"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/globalsearchv2"
	"github.com/IBM/platform-services-go-sdk/globaltaggingv1"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	utils "github.com/NetSys/invisinets/pkg/utils"
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

// returns IBMCloudClient instance with initialized clients
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
		utils.Log.Println("Failed to create vpc service client with error:\n", err)
		return nil, err
	}

	globalSearch, err := globalsearchv2.NewGlobalSearchV2(&globalsearchv2.GlobalSearchV2Options{
		Authenticator: authenticator,
	})
	if err != nil {
		utils.Log.Println("Failed to create global search client with error:\n", err)
		return nil, err
	}

	taggingService, err := globaltaggingv1.NewGlobalTaggingV1(&globaltaggingv1.GlobalTaggingV1Options{
		Authenticator: authenticator,
	})
	if err != nil {
		utils.Log.Println("Failed to create tagging client with error:\n", err)
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

// return image ID of default image
func (c *IBMCloudClient) getDefaultImageID() (imageID string, err error) {
	result, _, err := c.vpcService.ListImages(&vpcv1.ListImagesOptions{})
	if err != nil {
		utils.Log.Println("Failed to fetch VPC image collection with the",
			"following error:\n", err)
		return "", err
	}
	for _, image := range result.Images {
		if strings.HasPrefix(*image.Name, defaultImage) &&
			*image.OperatingSystem.Architecture == imageArchitecture {
			return *image.ID, nil
		}
	}
	utils.Log.Println("Failed to retrieve image named by prefix: ", defaultImage)
	return "", nil
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
		utils.Log.Println("tags search was invalid. Response\n", response)
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
