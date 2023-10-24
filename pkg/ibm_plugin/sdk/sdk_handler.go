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

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/globalsearchv2"
	"github.com/IBM/platform-services-go-sdk/globaltaggingv1"
	"github.com/IBM/vpc-go-sdk/vpcv1"

	utils "github.com/NetSys/invisinets/pkg/utils"
)

// CloudClient is the client used to interact with IBM Cloud SDK
type CloudClient struct {
	vpcService     *vpcv1.VpcV1
	region         string // region resources will be created in/fetched from
	globalSearch   *globalsearchv2.GlobalSearchV2
	taggingService *globaltaggingv1.GlobalTaggingV1
	resourceGroup  *vpcv1.ResourceGroupIdentityByID
}

func (c *CloudClient) Region() string {
	return c.region
}

// updates the vpc service's url service to the specified region
func (c *CloudClient) UpdateRegion(region string) error {
	c.region = region
	err := c.vpcService.SetServiceURL(endpointURL(region))
	if err != nil {
		return err
	}
	return nil
}

// returns CloudClient instance with initialized clients
func NewIBMCloudClient(name, region string) (*CloudClient, error) {
	if isRegionValid, err := IsRegionValid(region); !isRegionValid || err != nil {
		return nil, fmt.Errorf("region %v isn't valid", region)
	}
	creds, err := getIBMCred()
	if err != nil {
		return nil, err
	}

	apiKey := creds.APIKey
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

	resourceGroupID, err := getResourceID(authenticator, name)
	if err != nil {
		return nil, err
	}

	resourceGroupIdentity := &vpcv1.ResourceGroupIdentityByID{ID: resourceGroupID}

	client := CloudClient{
		vpcService:     api,
		region:         region,
		globalSearch:   globalSearch,
		taggingService: taggingService,
		resourceGroup:  resourceGroupIdentity,
	}
	return &client, nil
}

// GetInstanceID returns an instance ID given that name
func (c *CloudClient) GetInstanceID(name string) (string, error) {
	options := &vpcv1.ListInstancesOptions{Name: &name}
	collection, _, err := c.vpcService.ListInstances(options)
	if err != nil {
		return "", err
	}
	if len(collection.Instances) == 0 {
		return "", fmt.Errorf("instance %s not found", name)
	}
	return *collection.Instances[0].ID, nil
}

func (c *CloudClient) attachTag(CRN *string, tags []string) error {
	tags = append(tags, InvResourcePrefix)
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

// GetInvisinetsTaggedResources returns slice of IDs of tagged resources
// Arg resourceType: type of VPC resource, e.g. subnet, security group, instance.
// Arg tags: labels set by dev, e.g. {<vpcID>,<deploymentID>}
// Args customQueryMap: map of attributes to filter by, e.g. {"region":"<regionName>"}
func (c *CloudClient) GetInvisinetsTaggedResources(resourceType TaggedResourceType, tags []string,
	customQuery ResourceQuery) ([]string, error) {
	// parse tags
	var tagsStr string
	var queryStr string
	tags = append(tags, InvResourcePrefix) // append the invisinets tag
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
func (c *CloudClient) getInvisinetsResourceByTags(resourceType string,
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
