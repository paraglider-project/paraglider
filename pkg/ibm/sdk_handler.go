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

	k8sv1 "github.com/IBM-Cloud/container-services-go-sdk/kubernetesserviceapiv1"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/networking-go-sdk/transitgatewayapisv1"
	"github.com/IBM/platform-services-go-sdk/globalsearchv2"
	"github.com/IBM/platform-services-go-sdk/globaltaggingv1"
	"github.com/IBM/vpc-go-sdk/vpcv1"

	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

// CloudClient is the client used to interact with IBM Cloud SDK
type CloudClient struct {
	vpcService     *vpcv1.VpcV1
	k8sService     *k8sv1.KubernetesServiceApiV1
	region         string // region resources will be created in/fetched from
	globalSearch   *globalsearchv2.GlobalSearchV2
	taggingService *globaltaggingv1.GlobalTaggingV1
	resourceGroup  *vpcv1.ResourceGroupIdentityByID // required mainly to create/delete resources
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

// NewIBMCloudClient returns CloudClient instance with initialized clients
// Note: This will be used by IBM plugin through setupCloudClient, and
// should not be used directly to create a cloud client otherwise.
func NewIBMCloudClient(resourceGroupID, region string) (*CloudClient, error) {
	if isRegionValid, err := isRegionValid(region); !isRegionValid || err != nil {
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

	k8sService, err := k8sv1.NewKubernetesServiceApiV1(&k8sv1.KubernetesServiceApiV1Options{
		Authenticator: authenticator,
	})
	if err != nil {
		utils.Log.Println("Failed to create k8s service client with error:\n", err)
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
		k8sService:     k8sService,
		region:         region,
		globalSearch:   globalSearch,
		taggingService: taggingService,
		resourceGroup:  resourceGroupIdentity,
		transitGW:      transitGatewayService,
	}
	return &client, nil
}

// FakeIBMCloudClient returns a fake/mock CloudClient instance without auth, that needs to be handled in the URL
func FakeIBMCloudClient(fakeURL, fakeResGroupID, fakeRegion string) (*CloudClient, error) {
	noAuth, err := core.NewNoAuthAuthenticator()
	if err != nil {
		return nil, err
	}
	vpcService, err := vpcv1.NewVpcV1UsingExternalConfig(&vpcv1.VpcV1Options{
		Authenticator: noAuth,
		URL:           fakeURL,
	})
	if err != nil {
		return nil, err
	}

	k8sService, err := k8sv1.NewKubernetesServiceApiV1(&k8sv1.KubernetesServiceApiV1Options{
		Authenticator: noAuth,
		URL:           fakeURL,
	})
	if err != nil {
		utils.Log.Println("Failed to create k8s service client with error:\n", err)
		return nil, err
	}

	globalSearch, err := globalsearchv2.NewGlobalSearchV2UsingExternalConfig(&globalsearchv2.GlobalSearchV2Options{
		Authenticator: noAuth,
		URL:           fakeURL,
	})
	if err != nil {
		return nil, err
	}

	taggingService, err := globaltaggingv1.NewGlobalTaggingV1UsingExternalConfig(&globaltaggingv1.GlobalTaggingV1Options{
		Authenticator: noAuth,
		URL:           fakeURL,
	})
	if err != nil {
		utils.Log.Println("Failed to create tagging client with error:\n", err)
		return nil, err
	}

	resID := fakeResGroupID
	resourceGroupIdentity := &vpcv1.ResourceGroupIdentityByID{ID: &resID}

	transitGatewayService, err := transitgatewayapisv1.NewTransitGatewayApisV1UsingExternalConfig(&transitgatewayapisv1.TransitGatewayApisV1Options{
		Authenticator: noAuth,
		URL:           fakeURL,
		Version:       core.StringPtr("2023-12-05"), // version is a mandatory field
	})
	if err != nil {
		return nil, err
	}

	client := CloudClient{
		vpcService:     vpcService,
		k8sService:     k8sService,
		region:         fakeRegion,
		globalSearch:   globalSearch,
		taggingService: taggingService,
		resourceGroup:  resourceGroupIdentity,
		transitGW:      transitGatewayService,
	}
	return &client, nil
}

// GetZonesOfRegion returns zones of specified region
func (c CloudClient) GetZonesOfRegion(region string) ([]string, error) {
	zones := []string{}
	zoneCollection, _, err := c.vpcService.ListRegionZones(&vpcv1.ListRegionZonesOptions{RegionName: core.StringPtr(region)})
	if err != nil {
		return nil, err
	}
	for _, zone := range zoneCollection.Zones {
		zones = append(zones, *zone.Name)
	}
	return zones, nil
}
