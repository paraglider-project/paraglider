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
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
)

const (
	allowRule = armnetwork.SecurityRuleAccessAllow
	denyRule  = armnetwork.SecurityRuleAccessDeny
	inboundDirectionRule = armnetwork.SecurityRuleDirectionInbound
	outboundDirectionRule = armnetwork.SecurityRuleDirectionOutbound
)

// Checks that the NSG rules are conformant. Such that
//  1. A deny all rule is present and has the lowest priority (i.e. highest priority number)
//  2. All rules with higher priority (i.e. lower priority number) are allow rules
//
// Returns true if the rules conform to Paraglider's requirements, false otherwise.
// If false, the returned priority number is used to create a deny all rule to ensure conformance.
//
// Priority number of -1 represents an invalid rule order.
func validatePermitRulesConform(reservedPriorities map[int32]*armnetwork.SecurityRule) (bool, int32) {
	var lowestRule *armnetwork.SecurityRule
	lowestPriority := int32(maxPriority)

	for priority, rule := range reservedPriorities {
		// An allow rule's priority number is higher than a deny rule's priority number
		if priority < lowestPriority && *rule.Properties.Access == armnetwork.SecurityRuleAccessAllow {
			return false, -1
		}

		if priority <= lowestPriority && *rule.Properties.Access == armnetwork.SecurityRuleAccessDeny {
			lowestRule = rule
			lowestPriority = priority
		}
	}

	// No deny rule exists in the NSG, so non-conformant
	if lowestRule == nil {
		if reservedPriorities[maxPriority] != nil {
			// The max priority number should not be associated to an allow rule
			return false, -1
		}

		return false, maxPriority
	}

	// If not a deny all rule, return priority to create a deny all rule
	if !isDenyAllRule(lowestRule) {
		lastPriority := getPriority(reservedPriorities, minPriority, maxPriority, false)
		return false, lastPriority
	}

	return true, lowestPriority
}

func setupDenyAllRuleWithPriority(priority int32, direction armnetwork.SecurityRuleDirection) *armnetwork.SecurityRule {
	var suffix string
	if direction == inboundDirectionRule {
		suffix = "-inbound"
	} else {
		suffix = "-outbound"
	}

	return &armnetwork.SecurityRule{
		Name: to.Ptr(denyAllNsgRulePrefix + suffix),
		Properties: &armnetwork.SecurityRulePropertiesFormat{
			Access:                   to.Ptr(armnetwork.SecurityRuleAccessDeny),
			SourceAddressPrefix:      to.Ptr(azureSecurityRuleAsterisk),
			DestinationAddressPrefix: to.Ptr(azureSecurityRuleAsterisk),
			DestinationPortRange:     to.Ptr(azureSecurityRuleAsterisk),
			Direction:                to.Ptr(direction),
			Priority:                 to.Ptr(priority),
			Protocol:                 to.Ptr(armnetwork.SecurityRuleProtocolAsterisk),
			SourcePortRange:          to.Ptr(azureSecurityRuleAsterisk),
		},
	}
}

func isDenyAllRule(rule *armnetwork.SecurityRule) bool {
	return *rule.Properties.SourceAddressPrefix == azureSecurityRuleAsterisk &&
		*rule.Properties.DestinationAddressPrefix == azureSecurityRuleAsterisk &&
		*rule.Properties.SourcePortRange == azureSecurityRuleAsterisk &&
		*rule.Properties.DestinationPortRange == azureSecurityRuleAsterisk &&
		*rule.Properties.Protocol == armnetwork.SecurityRuleProtocolAsterisk &&
		*rule.Properties.Direction == azureSecurityRuleAsterisk &&
		*rule.Properties.Access == armnetwork.SecurityRuleAccessDeny
}
