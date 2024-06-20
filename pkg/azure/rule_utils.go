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
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

const (
	allowRule             = armnetwork.SecurityRuleAccessAllow
	denyRule              = armnetwork.SecurityRuleAccessDeny
	inboundDirectionRule  = armnetwork.SecurityRuleDirectionInbound
	outboundDirectionRule = armnetwork.SecurityRuleDirectionOutbound
)

// Checks that the NSG rules are conformant. Such that
//  1. A deny all rule is present and has the lowest priority (i.e. highest priority number)
//  2. All rules with higher priority (i.e. lower priority number) are allow rules
//
// Creates a deny all rule if there's none to ensure conformant rules for condition 1).
func CheckSecurityRulesCompliance(ctx context.Context, azureHandler *AzureSDKHandler, networkInfo *resourceNetworkInfo, namespace string, server *azurePluginServer) (bool, error) {
	reservedPrioritiesInbound := make(map[int32]*armnetwork.SecurityRule)
	reservedPrioritiesOutbound := make(map[int32]*armnetwork.SecurityRule)
	err := setupMaps(reservedPrioritiesInbound, reservedPrioritiesOutbound, nil, networkInfo.NSG)
	if err != nil {
		utils.Log.Printf("An error occured during setup: %+v", err)
		return false, err
	}

	// For Inbound Rules
	priority, err := validateSecurityRulesConform(reservedPrioritiesInbound)
	if err != nil {
		if priority == -1 {
			return false, fmt.Errorf("Non-compliant: %v", err)
		}

		_, err := setupAndCreateDenyAllRule(ctx, priority, inboundDirectionRule, azureHandler, networkInfo)
		if err != nil {
			return false, err
		}
	}

	// For Outbound Rules
	priority, err = validateSecurityRulesConform(reservedPrioritiesOutbound)
	if err != nil {
		if priority == -1 {
			return false, fmt.Errorf("Non-compliant: %v", err)
		}

		_, err := setupAndCreateDenyAllRule(ctx, priority, outboundDirectionRule, azureHandler, networkInfo)
		if err != nil {
			return false, err
		}
	}

	return true, nil
}

// Checks that the NSG rules in a particular direction are conformant as per the description of (func) CheckSecurityRulesCompliance
//
// Returns the priority number of the deny all rule if it exists (with no error)
// Or the priority number of the deny all rule to be created if the rules are non-conformant (with an error)
// Or a priority number of -1 (with an error) to represent an invalid rule order.
func validateSecurityRulesConform(reservedPriorities map[int32]*armnetwork.SecurityRule) (int32, error) {
	var lowestRule *armnetwork.SecurityRule
	lowestDenyPriorityNum := int32(maxPriority)
	highestAllowPriorityNum := int32(minPriority)

	for priority, rule := range reservedPriorities {
		if (*rule.Properties.Access == armnetwork.SecurityRuleAccessAllow) && (priority > highestAllowPriorityNum) {
			highestAllowPriorityNum = priority
		}

		if (*rule.Properties.Access == armnetwork.SecurityRuleAccessDeny) && (priority <= lowestDenyPriorityNum) {
			lowestRule = rule
			lowestDenyPriorityNum = priority
		}
	}

	// An allow rule's priority number is higher than a deny rule's priority number
	if highestAllowPriorityNum > lowestDenyPriorityNum {
		return -1, fmt.Errorf("Allow Rule with lower priority(%d) than Deny Rule(%d)", highestAllowPriorityNum, lowestDenyPriorityNum)
	}

	// No deny rule exists in the NSG, so non-conformant
	if lowestRule == nil {
		if reservedPriorities[maxPriority] != nil {
			// The max priority number should not be associated to an allow rule
			return -1, fmt.Errorf("Allow Rule at lowest priority(%d). Must be a deny all rule", maxPriority)
		}

		return maxPriority, fmt.Errorf("No deny rule present ")
	}

	// If not a deny all rule, return priority to create a deny all rule
	if !isDenyAllRule(lowestRule) {
		lastPriority := getPriority(reservedPriorities, minPriority, maxPriority, false)
		return lastPriority, fmt.Errorf("Deny Rule not at lowest priority(%d) is not a Deny all rule", lowestDenyPriorityNum)
	}

	return lowestDenyPriorityNum, nil
}

func setupAndCreateDenyAllRule(ctx context.Context, priority int32, direction armnetwork.SecurityRuleDirection, handler *AzureSDKHandler, netInfo *resourceNetworkInfo) (*armnetwork.SecurityRule, error) {
	denyAllRule := setupDenyAllRuleWithPriority(priority, direction)
	rule, err := handler.CreateSecurityRule(ctx, *netInfo.NSG.Name, *denyAllRule.Name, denyAllRule)
	if err != nil {
		return nil, err
	}

	return rule, nil
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

// Returns true if the rule is a deny all rule, false otherwise
func isDenyAllRule(rule *armnetwork.SecurityRule) bool {
	var anyDestPrefix, anySourcePrefix bool
	destPrefix := rule.Properties.DestinationAddressPrefix
	if destPrefix != nil && *destPrefix == azureSecurityRuleAsterisk {
		anyDestPrefix = true
	} else if rule.Properties.DestinationAddressPrefixes != nil {
		for _, destPrefix := range rule.Properties.DestinationAddressPrefixes {
			if *destPrefix == azureSecurityRuleAsterisk {
				anyDestPrefix = true
				break
			}
		}
	}

	sourcePrefix := rule.Properties.SourceAddressPrefix
	if sourcePrefix != nil && *sourcePrefix == azureSecurityRuleAsterisk {
		anySourcePrefix = true
	} else if rule.Properties.SourceAddressPrefixes != nil {
		for _, sourcePrefix := range rule.Properties.SourceAddressPrefixes {
			if *sourcePrefix == azureSecurityRuleAsterisk {
				anySourcePrefix = true
				break
			}
		}
	}

	return anyDestPrefix && anySourcePrefix &&
		*rule.Properties.SourcePortRange == azureSecurityRuleAsterisk &&
		*rule.Properties.DestinationPortRange == azureSecurityRuleAsterisk &&
		*rule.Properties.Protocol == armnetwork.SecurityRuleProtocolAsterisk &&
		*rule.Properties.Access == armnetwork.SecurityRuleAccessDeny
}
