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

package main

import (
	"testing"
)

func TestGetIPs(t *testing.T) {
	// 	tests := []struct {
	// 		name       string
	// 		rule       *invisinetspb.PermitListRule
	// 		resourceIP string
	// 		wantSrcIP  string
	// 		wantDestIP string
	// 	}{
	// 		{
	// 			name: "inbound rule",
	// 			rule: &invisinetspb.PermitListRule{
	// 				Direction: invisinetspb.Direction_INBOUND,
	// 				Tag:       "10.0.0.1",
	// 			},
	// 			resourceIP: "10.0.0.2",
	// 			wantSrcIP:  "10.0.0.1",
	// 			wantDestIP: "10.0.0.2",
	// 		},
	// 		{
	// 			name: "outbound rule",
	// 			rule: &invisinetspb.PermitListRule{
	// 				Direction: invisinetspb.Direction_INBOUND,
	// 				Tag:       "10.0.0.1",
	// 			},
	// 			resourceIP: "10.0.0.2",
	// 			wantSrcIP:  "10.0.0.2",
	// 			wantDestIP: "10.0.0.1",
	// 		},
	// 	}

	// 	for _, tt := range tests {
	// 		t.Run(tt.name, func(t *testing.T) {
	// 			srcIP, destIP := getIPs(tt.rule, tt.resourceIP)
	// 			if srcIP != tt.wantSrcIP {
	// 				t.Errorf("getIPs() srcIP = %v, want %v", srcIP, tt.wantSrcIP)
	// 			}
	// 			if destIP != tt.wantDestIP {
	// 				t.Errorf("getIPs() destIP = %v, want %v", destIP, tt.wantDestIP)
	// 			}
	// 		})
	// 	}
}

func TestGetLastSegment(t *testing.T) {
	tests := []struct {
		name    string
		ID      string
		want    string
		wantErr bool
	}{
		{
			name:    "valid ID",
			ID:      "/subscriptions/123/resourceGroups/my-group",
			want:    "my-group",
			wantErr: false,
		},
		{
			name:    "empty ID",
			ID:      "/",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetLastSegment(tt.ID)
			if (err != nil) != tt.wantErr {
				t.Errorf("getLastSegment() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getLastSegment() = %v, want %v", got, tt.want)
			}
		})
	}
}
