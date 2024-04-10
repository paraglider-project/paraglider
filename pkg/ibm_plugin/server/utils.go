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

	sdk "github.com/NetSys/invisinets/pkg/ibm_plugin/sdk"
)

// ResourceIDInfo defines the necessary fields of a resource sent in a request
type ResourceIDInfo struct {
	ResourceGroup string `json:"resourcegroup"` // name of the resource group
	Zone          string `json:"zone"`
	ResourceID    string `json:"resourceid"`
}

func getClientMapKey(resGroup, region string) string {
	return resGroup + "-" + region
}

// returns ResourceIDInfo out of an agreed upon formatted string:
// "/resourcegroup/{ResourceGroupName}/zone/{zone}/resourcetype/{ResourceID}"
func getResourceIDInfo(resourceID string) (ResourceIDInfo, error) {
	parts := strings.Split(resourceID, "/")

	if parts[0] != "" || parts[1] != "resourcegroup" {
		return ResourceIDInfo{}, fmt.Errorf("invalid resource ID format: expected '/resourcegroup/{ResourceGroup}', got '%s'", resourceID)
	}

	info := ResourceIDInfo{
		ResourceGroup: parts[2],
	}
	if len(parts) >= 4 {
		info.Zone = parts[4]
	}
	if len(parts) >= 5 {
		info.ResourceID = parts[6]
	}

	return info, nil
}

func createInstanceID(resGroup, zone, resName string) string {
	return fmt.Sprintf("/resourcegroup/%s/zone/%s/instances/%s", resGroup, zone, resName)
}

// returns the invisinets VPC that the specified remote (IP/CIDR) resides in.
func getRemoteVPC(remote, resourceGroup string) (*sdk.ResourceData, error) {

	// using a tmp client to avoid altering the cloud client's region.
	// passing a random region to pass verification. region will be updated with accordance to the selected VPC.
	tmpClient, err := sdk.NewIBMCloudClient(resourceGroup, "us-south", false)
	if err != nil {
		return nil, err
	}

	// fetching VPCs from all namespaces
	vpcsData, err := tmpClient.GetInvisinetsTaggedResources(sdk.VPC, []string{}, sdk.ResourceQuery{})
	if err != nil {
		return nil, err
	}

	// go over candidate VPCs address spaces
	for _, vpcData := range vpcsData {
		curVpcID := vpcData.ID

		// Set the client on the region of the current VPC. If the client's region is
		// different than the VPC's, it won't be detected.
		err := tmpClient.UpdateRegion(vpcData.Region)
		if err != nil {
			return nil, err
		}

		if isRemoteInVPC, err := tmpClient.IsRemoteInVPC(curVpcID, remote); isRemoteInVPC {
			return &vpcData, nil
		} else if err != nil {
			return nil, err
		}
	}
	// remote doesn't reside in any invisinets VPC
	return nil, nil
}
