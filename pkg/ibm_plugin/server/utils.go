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
	"context"
	"fmt"
	"strings"

	"github.com/paraglider-project/paraglider/pkg/paragliderpb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
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
func getResourceIDInfo(deploymentID string) (ResourceIDInfo, error) {
	parts := strings.Split(deploymentID, "/")

	if parts[0] != "" || parts[1] != "resourcegroup" {
		return ResourceIDInfo{}, fmt.Errorf("invalid resource ID format: expected '/resourcegroup/{ResourceGroup}', got '%s'", deploymentID)
	}

	info := ResourceIDInfo{
		ResourceGroup: parts[2],
	}

	if len(parts) >= 4 {
		if parts[3] != "zone" {
			return ResourceIDInfo{}, fmt.Errorf("invalid resource ID format: expected '/resourcegroup/{ResourceGroup}/zone/{zone}', got '%s'", deploymentID)
		}
		info.Zone = parts[4]
	}

	if len(parts) >= 5 {
		// In future, validate multiple resource type
		if parts[5] != instanceResourceType {
			return ResourceIDInfo{}, fmt.Errorf("invalid resource ID format: expected '/resourcegroup/{ResourceGroup}/zone/{zone}/instance/{instance_id}', got '%s'", deploymentID)
		}
		info.ResourceID = parts[6]
	}

	return info, nil
}

func createInstanceID(resGroup, zone, resName string) string {
	return fmt.Sprintf("/resourcegroup/%s/zone/%s/%s/%s", resGroup, zone, instanceResourceType, resName)
}

func setRuleValToStore(ctx context.Context, client paragliderpb.ControllerClient, key, value, namespace string) error {
	setVal := &paragliderpb.SetValueRequest{
		Key:       key,
		Value:     value,
		Cloud:     utils.IBM,
		Namespace: namespace,
	}
	_, err := client.SetValue(ctx, setVal)

	return err
}

func getRuleValFromStore(ctx context.Context, client paragliderpb.ControllerClient, key, namespace string) (string, error) {
	getVal := &paragliderpb.GetValueRequest{
		Key:       key,
		Cloud:     utils.IBM,
		Namespace: namespace,
	}
	resp, err := client.GetValue(ctx, getVal)

	if err != nil {
		return "", err
	}
	return resp.Value, err
}

func delRuleValFromStore(ctx context.Context, client paragliderpb.ControllerClient, key, namespace string) error {
	delVal := &paragliderpb.DeleteValueRequest{
		Key:       key,
		Cloud:     utils.IBM,
		Namespace: namespace,
	}
	_, err := client.DeleteValue(ctx, delVal)

	return err
}
