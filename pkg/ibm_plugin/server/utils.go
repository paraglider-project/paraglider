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

const (
	instanceResourceType = "instance"
)

// ResourceIDInfo defines the necessary fields of a resource sent in a request
type ResourceIDInfo struct {
	ResourceGroup string `json:"resourcegroup"`
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
		if parts[3] != "zone" {
			return ResourceIDInfo{}, fmt.Errorf("invalid resource ID format: expected '/resourcegroup/{ResourceGroup}/zone/{zone}', got '%s'", resourceID)
		}
		info.Zone = parts[4]
	}

	if len(parts) >= 5 {
		// In future, validate multiple resource type
		if parts[5] != instanceResourceType {
			return ResourceIDInfo{}, fmt.Errorf("invalid resource ID format: expected '/resourcegroup/{ResourceGroup}/zone/{zone}/instance/{instance_id}', got '%s'", resourceID)
		}
		info.ResourceID = parts[6]
	}

	return info, nil
}

func createInstanceID(resGroup, zone, resName string) string {
	return fmt.Sprintf("/resourcegroup/%s/zone/%s/%s/%s", resGroup, zone, instanceResourceType, resName)
}
