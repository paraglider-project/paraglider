package gcp

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/protobuf/proto"
)

func TestCheckFirewallRulesCompliance(t *testing.T) {
	tests := []struct {
		name        string
		firewalls   []*computepb.Firewall
		expected    bool
		expectedErr string
	}{
		{
			name: "Valid deny-all rule and compliant allow rules",
			firewalls: []*computepb.Firewall{
				{
					Priority:        proto.Int32(100),
					Allowed:         []*computepb.Allowed{{IPProtocol: proto.String("tcp")}},
					Denied:          nil,
					DestinationRanges: []string{"0.0.0.0/0"},
				},
				{
					Priority:        proto.Int32(200),
					Allowed:         nil,
					Denied:          []*computepb.Denied{{IPProtocol: proto.String("all")}},
					DestinationRanges: []string{"0.0.0.0/0"},
				},
				{
					Priority:        proto.Int32(300),
					Allowed:         []*computepb.Allowed{{IPProtocol: proto.String("icmp")}},
					Denied:          nil,
					DestinationRanges: []string{"0.0.0.0/0"},
				},
			},
			expected:    true,
			expectedErr: "",
		},
		{
			name: "No deny-all rule",
			firewalls: []*computepb.Firewall{
				{
					Priority:        proto.Int32(100),
					Allowed:         []*computepb.Allowed{{IPProtocol: proto.String("tcp")}},
					Denied:          nil,
					DestinationRanges: []string{"0.0.0.0/0"},
				},
			},
			expected:    false,
			expectedErr: "no deny-all rule found",
		},
		{
			name: "Deny-all rule with invalid destination range",
			firewalls: []*computepb.Firewall{
				{
					Priority:        proto.Int32(200),
					Allowed:         nil,
					Denied:          []*computepb.Denied{{IPProtocol: proto.String("all")}},
					DestinationRanges: []string{"192.168.0.0/16"},
				},
			},
			expected:    false,
			expectedErr: "no deny-all rule found",
		},

	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compliant, err := CheckFirewallRulesCompliance(tt.firewalls)
			if tt.expectedErr != "" {
				require.Error(t, err)
				assert.Equal(t, tt.expectedErr, err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, compliant)
			}
		})
	}
}

func TestIsDenyAllRule(t *testing.T) {
	tests := []struct {
		name      string
		firewall  *computepb.Firewall
		expect    bool
	}{
		{
			name: "Deny rule",
			firewall: &computepb.Firewall{
				Priority:        proto.Int32(lowestPriority),
				Allowed:         nil,
				Denied:          []*computepb.Denied{{IPProtocol: proto.String("all")}},
				DestinationRanges: []string{"0.0.0.0/0"},
			},
			expect: true,
		},
		{
			name: "Has no Denied",
			firewall: &computepb.Firewall{
				Priority:        proto.Int32(lowestPriority),
				Allowed:         nil,
				Denied:          nil,
				DestinationRanges: []string{"0.0.0.0/0"},
			},
			expect: false,
		},
		{
			name: "Has Denied but also has Allowed",
			firewall: &computepb.Firewall{
				Priority:        proto.Int32(lowestPriority),
				Allowed:         []*computepb.Allowed{{IPProtocol: proto.String("tcp")}},
				Denied:          []*computepb.Denied{{IPProtocol: proto.String("all")}},
				DestinationRanges: []string{"0.0.0.0/0"},
			},
			expect: false,
		},
		{
			name: "Denied protocol is not 'all'",
			firewall: &computepb.Firewall{
				Priority:        proto.Int32(lowestPriority),
				Allowed:         nil,
				Denied:          []*computepb.Denied{{IPProtocol: proto.String("tcp")}},
				DestinationRanges: []string{"0.0.0.0/0"},
			},
			expect: false,
		},
		{
			name: "Invalid destination range",
			firewall: &computepb.Firewall{
				Priority:        proto.Int32(lowestPriority),
				Allowed:         nil,
				Denied:          []*computepb.Denied{{IPProtocol: proto.String("all")}},
				DestinationRanges: []string{"192.168.0.0/16"},
			},
			expect: false,
		},
		{
			name: "No rule",
			expect: false,
		},
		{
			name: "No rule",
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isDenyAllRule(tt.firewall)
			assert.Equal(t, tt.expect, result)
		})
	}
}