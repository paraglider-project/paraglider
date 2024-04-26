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
			resourceID:   "/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Compute/virtualMachines/vm123",
			expectedInfo: ResourceIDInfo{SubscriptionID: "sub123", ResourceGroupName: "rg123", ResourceName: fakeVmName},
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
			resourceID:   "/subscriptions/sub123/invalidSegment/rg123/providers/Microsoft.Compute/virtualMachines/" + fakeVmName,
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
