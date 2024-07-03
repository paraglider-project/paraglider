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

package gcp

import (
	"fmt"
	"strconv"
	"strings"

	computepb "cloud.google.com/go/compute/apiv1/computepb"
	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
	"google.golang.org/protobuf/proto"
)

const (
	firewallNameMaxLength         = 62                // GCP imposed max length for firewall name
	firewallRuleDescriptionPrefix = "paraglider rule" // GCP firewall rule prefix for description
	targetTypeTag                 = "TAG"
	targetTypeAddress             = "ADDRESS"
)

// Maps between of GCP and Paraglider traffic direction terminologies
var (
	firewallDirectionMapGCPToParaglider = map[string]paragliderpb.Direction{
		"INGRESS": paragliderpb.Direction_INBOUND,
		"EGRESS":  paragliderpb.Direction_OUTBOUND,
	}

	firewallDirectionMapParagliderToGCP = map[paragliderpb.Direction]string{
		paragliderpb.Direction_INBOUND:  "INGRESS",
		paragliderpb.Direction_OUTBOUND: "EGRESS",
	}
)

// Maps protocol names that can appear in GCP firewall rules to IANA numbers (see https://cloud.google.com/firewall/docs/firewalls#protocols_and_ports)
var gcpProtocolNumberMap = map[string]int{
	"tcp":  6,
	"udp":  17,
	"icmp": 1,
	"esp":  50,
	"ah":   51,
	"sctp": 132,
	"ipip": 94,
}

type firewallTarget struct {
	TargetType string
	Target     string
}

// Checks if GCP firewall rule is a Paraglider permit list rule
func isParagliderPermitListRule(namespace string, firewall *computepb.Firewall) bool {
	return strings.HasSuffix(*firewall.Network, getVpcName(namespace)) && strings.HasPrefix(*firewall.Name, getFirewallNamePrefix(namespace))
}

// Converts a GCP firewall rule to a Paraglider permit list rule
func firewallRuleToParagliderRule(namespace string, fw *computepb.Firewall) (*paragliderpb.PermitListRule, error) {
	if len(fw.Allowed) != 1 {
		return nil, fmt.Errorf("firewall rule has more than one allowed protocol")
	}
	protocolNumber, err := getProtocolNumber(*fw.Allowed[0].IPProtocol)
	if err != nil {
		return nil, fmt.Errorf("could not get protocol number: %w", err)
	}

	direction := firewallDirectionMapGCPToParaglider[*fw.Direction]

	var targets []string
	if direction == paragliderpb.Direction_INBOUND {
		targets = append(fw.SourceRanges, fw.SourceTags...)
	} else {
		targets = fw.DestinationRanges
	}

	var dstPort int
	if len(fw.Allowed[0].Ports) == 0 {
		dstPort = -1
	} else {
		dstPort, err = strconv.Atoi(fw.Allowed[0].Ports[0])
		if err != nil {
			return nil, fmt.Errorf("could not convert port to int")
		}
	}

	var tags []string
	if fw.Description != nil {
		tags = parseDescriptionTags(*fw.Description)
	}

	rule := &paragliderpb.PermitListRule{
		Name:      parseFirewallName(namespace, *fw.Name),
		Direction: firewallDirectionMapGCPToParaglider[*fw.Direction],
		SrcPort:   -1,
		DstPort:   int32(dstPort),
		Protocol:  int32(protocolNumber),
		Targets:   targets,
		Tags:      tags,
	} // SrcPort not specified since GCP doesn't support rules based on source ports
	return rule, nil
}

// Converts a Paraglider permit list rule to a GCP firewall rule
func paragliderRuleToFirewallRule(namespace string, project string, firewallName string, target firewallTarget, rule *paragliderpb.PermitListRule) (*computepb.Firewall, error) {
	firewall := &computepb.Firewall{
		Allowed: []*computepb.Allowed{
			{
				IPProtocol: proto.String(strconv.Itoa(int(rule.Protocol))),
			},
		},
		Description: proto.String(getRuleDescription(rule.Tags)),
		Direction:   proto.String(firewallDirectionMapParagliderToGCP[rule.Direction]),
		Name:        proto.String(firewallName),
		Network:     proto.String(GetVpcUrl(project, namespace)),
	}

	// Associate with a tag if possible, otherwise match on IP
	if target.TargetType == targetTypeTag {
		firewall.TargetTags = []string{target.Target}
	} else {
		if rule.Direction == paragliderpb.Direction_INBOUND {
			firewall.DestinationRanges = []string{target.Target}
		} else {
			firewall.SourceRanges = []string{target.Target}
		}
	}

	if rule.DstPort != -1 {
		// Users must explicitly set DstPort to -1 if they want it to apply to all ports since proto can't
		// differentiate between empty and 0 for an int field. Ports of 0 are valid for protocols like TCP/UDP.
		firewall.Allowed[0].Ports = []string{strconv.Itoa(int(rule.DstPort))}
	}
	if rule.Direction == paragliderpb.Direction_INBOUND {
		// TODO @seankimkdy: use SourceTags as well once we start supporting tags
		firewall.SourceRanges = rule.Targets
	} else {
		firewall.DestinationRanges = rule.Targets
	}
	return firewall, nil
}

// Determine if a firewall rule and permit list rule are equivalent
func isFirewallEqPermitListRule(namespace string, firewall *computepb.Firewall, rule *paragliderpb.PermitListRule) (bool, error) {
	paragliderVersion, err := firewallRuleToParagliderRule(namespace, firewall)
	if err != nil {
		return false, fmt.Errorf("could not convert firewall rule to permit list rule: %w", err)
	}

	targetMap := map[string]bool{}
	for _, target := range paragliderVersion.Targets {
		targetMap[target] = true
	}

	for _, target := range rule.Targets {
		if !targetMap[target] {
			return false, nil
		}
	}

	return paragliderVersion.Name == rule.Name &&
		paragliderVersion.Direction == rule.Direction &&
		paragliderVersion.Protocol == rule.Protocol &&
		paragliderVersion.DstPort == rule.DstPort &&
		paragliderVersion.SrcPort == rule.SrcPort, nil
}

// Gets protocol number from GCP specificiation (either a name like "tcp" or an int-string like "6")
func getProtocolNumber(firewallProtocol string) (int32, error) {
	protocolNumber, ok := gcpProtocolNumberMap[firewallProtocol]
	if !ok {
		var err error
		protocolNumber, err = strconv.Atoi(firewallProtocol)
		if err != nil {
			return 0, fmt.Errorf("could not convert GCP firewall protocol to protocol number")
		}
	}
	return int32(protocolNumber), nil
}

// Gets a GCP firewall rule name for a Paraglider permit list rule
// If two Paraglider permit list rules are equal, then they will have the same GCP firewall rule name.
func getFirewallName(namespace string, ruleName string, resourceId string) string {
	return fmt.Sprintf("%s-%s-%s", getFirewallNamePrefix(namespace), resourceId, ruleName)
}

// Retrieve the name of the permit list rule from the GCP firewall name
func parseFirewallName(namespace string, firewallName string) string {
	fmt.Println(firewallName)
	fmt.Println(strings.TrimPrefix(firewallName, getFirewallNamePrefix(namespace)+"-"))
	return strings.SplitN(strings.TrimPrefix(firewallName, getFirewallNamePrefix(namespace)+"-"), "-", 2)[1]
}

// Returns name of firewall for denying all egress traffic
func getDenyAllIngressFirewallName(namespace string) string {
	return getParagliderNamespacePrefix(namespace) + "-deny-all-egress"
}

// Format the description to keep metadata about tags
func getRuleDescription(tags []string) string {
	if len(tags) == 0 {
		return firewallRuleDescriptionPrefix
	}
	return fmt.Sprintf("%s:%v", firewallRuleDescriptionPrefix, tags)
}

// Parses description string to get tags
func parseDescriptionTags(description string) []string {
	var tags []string
	if strings.HasPrefix(description, firewallRuleDescriptionPrefix+":[") {
		trimmedDescription := strings.TrimPrefix(description, firewallRuleDescriptionPrefix+":")
		trimmedDescription = strings.Trim(trimmedDescription, "[")
		trimmedDescription = strings.Trim(trimmedDescription, "]")
		tags = strings.Split(trimmedDescription, " ")
	}
	return tags
}

func getFirewallNamePrefix(namespace string) string {
	return getParagliderNamespacePrefix(namespace) + "-fw"
}
