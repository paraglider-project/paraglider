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
	"strconv"
	"strings"
	"time"

	"github.com/IBM/platform-services-go-sdk/globalsearchv2"
	"github.com/IBM/platform-services-go-sdk/globaltaggingv1"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

func (c *CloudClient) attachTag(CRN *string, tags []string) error {
	tags = append(tags, ParagliderTag) // add universal tag for paraglider' resources
	userTypeTag := globaltaggingv1.AttachTagOptionsTagTypeUserConst
	resourceModel := &globaltaggingv1.Resource{
		ResourceID:   CRN,
		ResourceType: &userTypeTag,
	}

	attachTagOptions := c.taggingService.NewAttachTagOptions(
		[]globaltaggingv1.Resource{*resourceModel},
	)
	attachTagOptions.SetTagNames(tags)

	// attach tags with retires.
	// retry mechanism improves stability and is needed due to possible temporary unavailability of resources, e.g. at time of creation.
	maxAttempts := 10 // retries number to tag a resource
	var err error
	var result *globaltaggingv1.TagResults
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		result, _, err = c.taggingService.AttachTag(attachTagOptions)
		// tracking all responses from error prone tagging service
		utils.Log.Printf("Tagging attempt %v: Error: %v", attempt, err)
		if !*result.Results[0].IsError {
			return nil
		}
		// sleep to avoid busy waiting
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("failed to tag resource : %v", err)
}

// GetParagliderTaggedResources returns slice of IDs of tagged resources
// Arg resourceType: type of VPC resource, e.g. subnet, security group, instance.
// Arg tags: labels set by dev, e.g. {<vpcID>,<deploymentID>}
// Args customQueryMap: map of attributes to filter by, e.g. {"region":"<regionName>"}
func (c *CloudClient) GetParagliderTaggedResources(resourceType TaggedResourceType, tags []string, customQuery ResourceQuery) ([]ResourceData, error) {
	// parse tags
	var tagsStr string
	var queryStr string
	// append the paraglider tag to narrow the search scope to paraglider resources only.
	tags = append(tags, ParagliderTag)
	for _, tag := range tags {
		tagsStr += fmt.Sprintf("tags:%v AND ", tag)
	}
	tagsStr = strings.TrimSuffix(tagsStr, "AND ") // remove last operator

	// Parse region/zone individually to accommodate unique behavior:
	// globalSearch returns the region field for all resources, although for some it holds
	// the zone value, e.g. subnet's region actually contain a zone's value.
	if customQuery.Zone != "" {
		queryStr += fmt.Sprintf("%v:%v AND ", "region", customQuery.Zone)
	} else if customQuery.Region != "" {
		queryStr += fmt.Sprintf("%v:%v* AND ", "region", customQuery.Region)
		// e.g. region:eu-de* would fetch all zones in eu-de for zone bound resources
	}

	if customQuery.CRN != "" {
		queryStr += fmt.Sprintf("%v:\"%v\" ", "crn", customQuery.CRN)
	}

	resourceList, err := c.getParagliderResourceByTags(string(resourceType), tagsStr, queryStr)
	if err != nil {
		return nil, err
	}
	return resourceList, nil
}

// returns IDs of resources filtered by tags and query
func (c *CloudClient) getParagliderResourceByTags(resourceType string, tags string, customQueryStr string) ([]ResourceData, error) {
	var taggedResources []ResourceData

	query := fmt.Sprintf("type:%v AND %v ", resourceType, tags)
	if customQueryStr != "" {
		query += "AND " + customQueryStr
	}

	result, err := c.getTaggedResources(query)
	if err != nil {
		return nil, err
	}

	items := result.Items
	if len(items) != 0 {
		for _, item := range items {
			resData := ResourceData{CRN: *item.CRN}
			id := CRN2ID(*item.CRN)
			itemProperties := item.GetProperties()
			if _, regionExists := itemProperties["region"]; regionExists {
				region := itemProperties["region"].(string)
				if len(region) != 0 {
					regionParts := strings.Split(region, "-")
					// since globalSearch.Search stores both region and zone in the region field,
					// we need to verify what the value represents
					if _, err := strconv.Atoi(regionParts[len(regionParts)-1]); err != nil {
						resData.Region = region
					} else {
						resData.Zone = region
					}
				}
			}
			resData.ID = id
			taggedResources = append(taggedResources, resData)
		}
	} else { // no resources found with specified tags
		return nil, nil
	}
	return taggedResources, nil
}

// returns tagged resource matching the specified query.
func (c *CloudClient) getTaggedResources(query string) (*globalsearchv2.ScanResult, error) {
	searchOptions := c.globalSearch.NewSearchOptions()
	searchOptions.SetLimit(100)
	searchOptions.SetQuery(query)
	searchOptions.SetFields([]string{"*"})

	// search tags with retries.
	// retry mechanism improves stability and is needed due to possible temporary unavailability of resources, e.g. at time of creation.
	maxAttempts := 10    // retries number to fetch a tagged resource
	latestResponse := "" // record latest response from inner scope
	for attempt := 1; attempt <= maxAttempts; attempt += 1 {
		res, response, err := c.globalSearch.Search(searchOptions)
		if err != nil {
			utils.Log.Printf("Tags search was invalid at attempt %v.\nResponse:%+v\nErr%+v\n", attempt, response, err)
		} else {
			return res, nil
		}
		// sleep to avoid busy waiting
		time.Sleep(5 * time.Second)
	}
	return nil, fmt.Errorf("Failed to tag resource with response:\n %+v", latestResponse)
}
