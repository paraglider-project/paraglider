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
)

// ResourceIDInfo defines the necessary fields of a resource sent in a request
type ResourceIDInfo struct {
	ResourceGroupName string `json:"ResourceGroupName"` // name of the resource group
	Zone              string `json:"Zone"`
	ResourceID        string `json:"ResourceID"`
}

func getClientMapKey(resGroup, region string) string {
	return resGroup + "-" + region
}

// returns ResourceIDInfo out of an agreed upon formatted string:
// "/ResourceGroupName/{ResourceGroupName}/Region/{Region}/ResourceID/{ResourceID}"
func getResourceIDInfo(resourceID string) (ResourceIDInfo, error) {
	parts := strings.Split(resourceID, "/")
	if len(parts) < 5 {
		return ResourceIDInfo{}, fmt.Errorf("invalid resource ID format: expected at least 5 parts in the format of '/ResourceGroupName/{ResourceGroupName}/Zone/{Zone}/ResourceID/{ResourceID}', got %d", len(parts))
	}

	if parts[0] != "" || parts[1] != "ResourceGroupName" || parts[3] != "Zone" {
		return ResourceIDInfo{}, fmt.Errorf("invalid resource ID format: expected '/ResourceGroupName/{ResourceGroupName}/Zone/{Zone}/ResourceID/{ResourceID}', got '%s'", resourceID)
	}

	info := ResourceIDInfo{
		ResourceGroupName: parts[2],
		Zone:              parts[4],
		ResourceID:        parts[6],
	}

	return info, nil
}

// Gets resource group name from Invisinets Deployment ID
func getResourceGroupName(deploymentID string) (string, error) {
	parts := strings.Split(deploymentID, "/")
	if len(parts) != 3 || parts[0] != "" || parts[1] != "ResourceGroupName" {
		return "", fmt.Errorf("invalid deployment ID format: expected format of '/ResourceGroupName/{ResourceGroupName}'")
	}
	return parts[2], nil
}
