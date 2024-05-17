//go:build unit

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
package azure

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetVnetFromSubnetId(t *testing.T) {
	subnetId := "/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Network/virtualNetworks/vnet123/subnets/subnet123"
	expectedVnet := "vnet123"

	vnet := getVnetFromSubnetId(subnetId)
	assert.Equal(t, expectedVnet, vnet)
}

func TestGetResourceIDInfo(t *testing.T) {
	tests := []struct {
		name         string
		resourceID   string
		expectedInfo ResourceIDInfo
		expectError  bool
	}{
		{
			name:         "ValidResourceIDWithVM",
			resourceID:   "/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Compute/virtualMachines/" + validVmName,
			expectedInfo: ResourceIDInfo{SubscriptionID: "sub123", ResourceGroupName: "rg123", ResourceName: validVmName},
			expectError:  false,
		},
		{
			name:         "ValidResourceIDWithoutVM",
			resourceID:   "/subscriptions/sub123/resourceGroups/rg123",
			expectedInfo: ResourceIDInfo{SubscriptionID: "sub123", ResourceGroupName: "rg123", ResourceName: "rg123"},
			expectError:  false,
		},
		{
			name:         "InvalidFormatTooFewSegments",
			resourceID:   "/subscriptions/sub123",
			expectedInfo: ResourceIDInfo{},
			expectError:  true,
		},
		{
			name:         "InvalidSegment",
			resourceID:   "/subscriptions/sub123/invalidSegment/rg123/providers/Microsoft.Compute/virtualMachines/" + validVmName,
			expectedInfo: ResourceIDInfo{},
			expectError:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info, err := getResourceIDInfo(test.resourceID)

			if test.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expectedInfo, info)
			}
		})
	}
}
