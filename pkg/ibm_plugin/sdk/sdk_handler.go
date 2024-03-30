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

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/networking-go-sdk/transitgatewayapisv1"
	"github.com/IBM/platform-services-go-sdk/globalsearchv2"
	"github.com/IBM/platform-services-go-sdk/globaltaggingv1"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	ibmCommon "github.com/NetSys/invisinets/pkg/ibm_plugin"

	utils "github.com/NetSys/invisinets/pkg/utils"
)

// CloudClient is the client used to interact with IBM Cloud SDK
type CloudClient struct {
	vpcService     *vpcv1.VpcV1
	region         string // region resources will be created in/fetched from
	globalSearch   *globalsearchv2.GlobalSearchV2
	taggingService *globaltaggingv1.GlobalTaggingV1
	resourceGroup  *vpcv1.ResourceGroupIdentityByID   // required mainly to create/delete resources
	transitGW      *transitgatewayapisv1.TransitGatewayApisV1
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
func NewIBMCloudClient(resourceGroupName, region string) (*CloudClient, error) {
	if isRegionValid, err := ibmCommon.IsRegionValid(region); !isRegionValid || err != nil {
		return nil, fmt.Errorf("region %v isn't valid", region)
	}

	authenticator, err := getAuthenticator()
	if err != nil {
		return nil, err
	}

	vpcService, err := vpcv1.NewVpcV1(&vpcv1.VpcV1Options{
		Authenticator: authenticator,
		URL:           endpointURL(region),
	})
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

	resourceGroupID, err := getResourceID(authenticator, resourceGroupName)
	if err != nil {
		return nil, err
	}

	resourceGroupIdentity := &vpcv1.ResourceGroupIdentityByID{ID: resourceGroupID}

	transitOptions := &transitgatewayapisv1.TransitGatewayApisV1Options{
		Version:       core.StringPtr("2023-12-05"), // version is a mandatory field
		Authenticator: authenticator,
	}

	transitGatewayService, err := transitgatewayapisv1.NewTransitGatewayApisV1(transitOptions)
	if err != nil {
		return nil, err
	}

	client := CloudClient{
		vpcService:     vpcService,
		region:         region,
		globalSearch:   globalSearch,
		taggingService: taggingService,
		resourceGroup:  resourceGroupIdentity,
		transitGW:      transitGatewayService,
	}
	return &client, nil
}
