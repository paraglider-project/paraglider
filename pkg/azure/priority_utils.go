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
	"math"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
)

// setupMaps fills the reservedPrioritiesInbound and reservedPrioritiesOutbound maps with the priorities of the existing rules in the NSG
// This is done to avoid priorities conflicts when creating new rules
// Existing rules map is filled to ensure that rules that just need their contents updated do not get recreated with new priorities
func setupMaps(reservedPrioritiesInbound map[int32]*armnetwork.SecurityRule, reservedPrioritiesOutbound map[int32]*armnetwork.SecurityRule, existingRulePriorities map[string]int32, nsg *armnetwork.SecurityGroup) error {
	for _, rule := range nsg.Properties.SecurityRules {
		if *rule.Properties.Direction == armnetwork.SecurityRuleDirectionInbound {
			reservedPrioritiesInbound[*rule.Properties.Priority] = rule
		} else if *rule.Properties.Direction == armnetwork.SecurityRuleDirectionOutbound {
			reservedPrioritiesOutbound[*rule.Properties.Priority] = rule
		}

		// skip rules that are added by default, because they may have different fields
		// such as port ranges which is not supported by Paraglider at the moment
		if existingRulePriorities == nil || *rule.Properties.Priority > maxPriority {
			continue
		}
		existingRulePriorities[*rule.Name] = *rule.Properties.Priority
	}
	return nil
}

// getPriority returns the next available priority number that is not used by other rules
func getPriority(reservedPriorities map[int32]*armnetwork.SecurityRule, start int32, end int32, ascendingSearch bool) int32 {
	if !ascendingSearch {
		start *= -1
		end *= -1
	}

	var i int32
	for i = start; i < end; i++ {
		i = int32(math.Abs(float64(i)))
		if reservedPriorities[i] == nil {
			reservedPriorities[i] = &armnetwork.SecurityRule{}
			break
		}
	}

	return i
}
