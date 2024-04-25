package azure

import (
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
)

// setupMaps fills the reservedPrioritiesInbound and reservedPrioritiesOutbound maps with the priorities of the existing rules in the NSG
// This is done to avoid priorities conflicts when creating new rules
// Existing rules map is filled to ensure that rules that just need their contents updated do not get recreated with new priorities
func setupMaps(reservedPrioritiesInbound map[int32]bool, reservedPrioritiesOutbound map[int32]bool, existingRulePriorities map[string]int32, nsg *armnetwork.SecurityGroup) error {
	for _, rule := range nsg.Properties.SecurityRules {
		if *rule.Properties.Direction == armnetwork.SecurityRuleDirectionInbound {
			reservedPrioritiesInbound[*rule.Properties.Priority] = true
		} else if *rule.Properties.Direction == armnetwork.SecurityRuleDirectionOutbound {
			reservedPrioritiesOutbound[*rule.Properties.Priority] = true
		}

		// skip rules that are not created by Invisinets, because some rules are added by default and have
		// different fields such as port ranges which is not supported by Invisinets at the moment
		if !strings.HasPrefix(*rule.Name, invisinetsPrefix) {
			continue
		}
		existingRulePriorities[*rule.Name] = *rule.Properties.Priority
	}
	return nil
}

// getPriority returns the next available priority that is not used by other rules
func getPriority(reservedPriorities map[int32]bool, start int32, end int32) int32 {
	var i int32
	for i = start; i < end; i++ {
		if !reservedPriorities[i] {
			reservedPriorities[i] = true
			break
		}
	}
	return i
}
