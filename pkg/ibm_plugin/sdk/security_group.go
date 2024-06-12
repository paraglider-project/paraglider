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
	"encoding/json"
	"fmt"
	"net"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	ibmCommon "github.com/paraglider-project/paraglider/pkg/ibm_plugin"

	"github.com/paraglider-project/paraglider/pkg/paragliderpb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

const (
	ipType   = "IP"
	cidrType = "CIDR"
	sgType   = "SG"

	sgResType = "sg"

	inboundType  = "inbound"
	outboundType = "outbound"
)

// SecurityGroupRule defines the entries of a security group rule
type SecurityGroupRule struct {
	ID         string // Unique identifier of this rule
	SgID       string // Unique ID of the security group to which this rule belongs
	Protocol   string // IP protocol that this rules applies to
	Remote     string // What this rule applies to (IP or CIDR block)
	RemoteType string // Type of remote, can be "IP", "CIDR", or "SG"
	PortMin    int64  // First port of the range to which this rule applies (only available for TCP/UDP rules), -1 means all ports
	PortMax    int64  // Last port of the range to which this rule applies (only available for TCP/UDP rules), -1 means all ports
	IcmpType   int64  // ICMP Type for the rule (only available for ICMP rules), -1 means all types
	IcmpCode   int64  // ICMP Code for the rule (only available for ICMP rules), -1 means all codes
	Egress     bool   // The rule affects to outbound traffic (true) or inbound (false)
}

// mapping paraglider traffic directions to booleans
var paragliderToIBMDirection = map[paragliderpb.Direction]bool{
	paragliderpb.Direction_OUTBOUND: true,
	paragliderpb.Direction_INBOUND:  false,
}

// mapping booleans paraglider traffic directions
var ibmToParagliderDirection = map[bool]paragliderpb.Direction{
	true:  paragliderpb.Direction_OUTBOUND,
	false: paragliderpb.Direction_INBOUND,
}

// mapping integers determined by the IANA standard to IBM protocols
var paragliderToIBMprotocol = map[int32]string{
	-1: "all",
	1:  "icmp",
	6:  "tcp",
	17: "udp",
}

// mapping IBM protocols to integers determined by the IANA standard
var ibmToParagliderProtocol = map[string]int32{
	"all":  -1,
	"icmp": 1,
	"tcp":  6,
	"udp":  17,
}

// creates security group in the specified VPC and tags it.
func (c *CloudClient) createSecurityGroup(
	vpcID string) (*vpcv1.SecurityGroup, error) {
	sgTags := []string{vpcID}

	vpcIdentity := vpcv1.VPCIdentityByID{ID: &vpcID}
	sgName := GenerateResourceName(sgResType)
	options := vpcv1.CreateSecurityGroupOptions{
		VPC:           &vpcIdentity,
		ResourceGroup: c.resourceGroup,
		Name:          &sgName,
	}
	sg, resp, err := c.vpcService.CreateSecurityGroup(&options)
	if err != nil {
		utils.Log.Printf("%s", resp)
		return nil, err
	}
	utils.Log.Printf("Created security group %v with id %v", sgName, *sg.ID)

	err = c.attachTag(sg.CRN, sgTags)
	if err != nil {
		utils.Log.Print("Failed to tag SG with error:", err)
		return nil, err
	}
	return sg, nil
}

func (c *CloudClient) getDefaultSecurityGroup(vpcID string) (*vpcv1.DefaultSecurityGroup, error) {
	vpc, _, err := c.vpcService.GetVPCDefaultSecurityGroup(c.vpcService.NewGetVPCDefaultSecurityGroupOptions(vpcID))
	if err != nil {
		return nil, err
	}
	return vpc, nil
}

// GetSecurityRulesOfSG gets the rules of security groups
func (c *CloudClient) GetSecurityRulesOfSG(sgID string) ([]SecurityGroupRule, error) {
	options := &vpcv1.ListSecurityGroupRulesOptions{}
	options.SetSecurityGroupID(sgID)
	rules, _, err := c.vpcService.ListSecurityGroupRules(options)
	if err != nil {
		return nil, err
	}
	return c.translateSecurityGroupRules(rules.Rules, sgID)
}

// returns SecurityGroupRule objects, converted from abstract rules
func (c *CloudClient) translateSecurityGroupRules(
	ibmRules []vpcv1.SecurityGroupRuleIntf, sgID string) ([]SecurityGroupRule, error) {

	rules := make([]SecurityGroupRule, len(ibmRules))
	for i, ibmRule := range ibmRules {
		rule, err := c.translateSecurityGroupRule(ibmRule, sgID)
		if err != nil {
			return nil, err
		} else {
			rules[i] = *rule
		}
	}
	return rules, nil
}

// translateSecurityGroupRule returns a SecurityGroupRule converted from vpcv1.SecurityGroupRuleIntf based on its concrete type
func (c *CloudClient) translateSecurityGroupRule(
	ibmRule vpcv1.SecurityGroupRuleIntf, sgID string) (*SecurityGroupRule, error) {
	switch ibmRule.(type) {
	case *vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolAll:
		return c.translateSecurityGroupRuleGroupRuleProtocolAll(ibmRule, sgID)
	case *vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp:
		return c.translateSecurityGroupRuleGroupRuleProtocolICMP(ibmRule, sgID)
	case *vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp:
		return c.translateSecurityGroupRuleGroupRuleProtocolTCPUDP(ibmRule, sgID)
	}
	return nil, nil
}

// translateSecurityGroupRuleGroupRuleProtocolAll returns SecurityGroupRule object converted from
// SecurityGroupRuleIntf, whose concrete type is SecurityGroupRuleSecurityGroupRuleProtocolAll
func (c *CloudClient) translateSecurityGroupRuleGroupRuleProtocolAll(
	ibmRule vpcv1.SecurityGroupRuleIntf, sgID string) (*SecurityGroupRule, error) {

	ibmRuleProtoAll := ibmRule.(*vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolAll)
	remote, remoteType, err := c.translateSecurityGroupRuleRemote(ibmRuleProtoAll.Remote)
	if err != nil {
		return nil, err
	}

	rule := SecurityGroupRule{
		ID:         *ibmRuleProtoAll.ID,
		Protocol:   *ibmRuleProtoAll.Protocol,
		SgID:       sgID,
		Remote:     remote,
		RemoteType: remoteType,
		Egress:     *ibmRuleProtoAll.Direction == outboundType,
		PortMin:    int64(-1),
		PortMax:    int64(-1),
	}
	return &rule, nil
}

// translateSecurityGroupRuleGroupRuleProtocolICMP returns SecurityGroupRule object converted from
// SecurityGroupRuleIntf, whose concrete type is SecurityGroupRuleSecurityGroupRuleProtocolIcmp
func (c *CloudClient) translateSecurityGroupRuleGroupRuleProtocolICMP(
	ibmRule vpcv1.SecurityGroupRuleIntf, sgID string) (*SecurityGroupRule, error) {

	ibmRuleIcmp := ibmRule.(*vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp)
	remote, remoteType, err := c.translateSecurityGroupRuleRemote(ibmRuleIcmp.Remote)
	if err != nil {
		return nil, err
	}
	isEgress := false
	if *ibmRuleIcmp.Direction == outboundType {
		isEgress = true
	}
	icmpCode := int64(-1)
	if ibmRuleIcmp.Code != nil { // rule allows specific icmp code
		icmpCode = *ibmRuleIcmp.Code
	}
	icmpType := int64(-1)
	if ibmRuleIcmp.Type != nil { // rule allows specific icmp type
		icmpType = *ibmRuleIcmp.Type
	}

	rule := SecurityGroupRule{
		ID:         *ibmRuleIcmp.ID,
		Protocol:   *ibmRuleIcmp.Protocol,
		SgID:       sgID,
		Remote:     remote,
		RemoteType: remoteType,
		IcmpCode:   icmpCode,
		IcmpType:   icmpType,
		Egress:     isEgress,
		// although ICMP protocol doesn't support ports, fields are required for rules comparison
		PortMin: -1,
		PortMax: -1,
	}
	return &rule, nil
}

// translateSecurityGroupRuleGroupRuleProtocolTCPUDP returns SecurityGroupRule object converted from
// SecurityGroupRuleIntf, whose concrete type is SecurityGroupRuleSecurityGroupRuleProtocolTcpudp
func (c *CloudClient) translateSecurityGroupRuleGroupRuleProtocolTCPUDP(
	ibmRule vpcv1.SecurityGroupRuleIntf, sgID string) (*SecurityGroupRule, error) {

	ibmRuleTCPUDP := ibmRule.(*vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp)
	remote, remoteType, err := c.translateSecurityGroupRuleRemote(ibmRuleTCPUDP.Remote)
	if err != nil {
		return nil, err
	}
	isEgress := false
	if *ibmRuleTCPUDP.Direction == "outbound" {
		isEgress = true
	}
	rule := SecurityGroupRule{
		ID:         *ibmRuleTCPUDP.ID,
		Protocol:   *ibmRuleTCPUDP.Protocol,
		SgID:       sgID,
		Remote:     remote,
		RemoteType: remoteType,
		Egress:     isEgress,
	}
	if ibmRuleTCPUDP.PortMin != nil && ibmRuleTCPUDP.PortMax != nil {
		rule.PortMin = *ibmRuleTCPUDP.PortMin
		rule.PortMax = *ibmRuleTCPUDP.PortMax
	}

	return &rule, nil
}

// returns remote(IP/CIDR address) and remote-type(IP/CIDR) of an abstract rule
func (c *CloudClient) translateSecurityGroupRuleRemote(
	ibmRuleRemoteIntf vpcv1.SecurityGroupRuleRemoteIntf) (string, string, error) {

	switch v := ibmRuleRemoteIntf.(type) {
	// According to the docs, the interface should map to a specific type,
	// but in this case it seems to just map to a generic "remote" where pointers may be nil
	case *vpcv1.SecurityGroupRuleRemote:
		ibmRuleRemote := ibmRuleRemoteIntf.(*vpcv1.SecurityGroupRuleRemote)
		if ibmRuleRemote.Address != nil {
			return *ibmRuleRemote.Address, ipType, nil
		}
		if ibmRuleRemote.CIDRBlock != nil {
			return *ibmRuleRemote.CIDRBlock, cidrType, nil
		}
		// For IBM Cloud, it is common to have an inbound rule accepting traffic
		// from a security group (sometimes the same where the rule belongs)
		if ibmRuleRemote.ID != nil {
			return *ibmRuleRemote.ID, sgType, nil
		}
	default:
		return "", "", fmt.Errorf(
			"unexpected type for security group rule remote [%T]", v,
		)
	}
	return "", "", fmt.Errorf(
		"unexpected type for security group rule remote [%T]",
		ibmRuleRemoteIntf,
	)
}

// AddSecurityGroupRule adds following functions are responsible for assigning SecurityGroupRules
// to a security group.
func (c *CloudClient) AddSecurityGroupRule(rule SecurityGroupRule) (string, error) {
	prototype, err := c.translateRuleProtocol(rule)
	if err != nil {
		return "", err
	}
	return c.addSecurityGroupRule(rule.SgID, prototype)
}

func (c *CloudClient) addSecurityGroupRule(sgID string, prototype vpcv1.SecurityGroupRulePrototypeIntf) (string, error) {

	options := vpcv1.CreateSecurityGroupRuleOptions{
		SecurityGroupID:            &sgID,
		SecurityGroupRulePrototype: prototype,
	}
	res, _, err := c.vpcService.CreateSecurityGroupRule(&options)
	if err != nil {
		return "", err
	}
	return c.getIBMRuleID(res), err
}

// returns an IBM abstract rule object, converted from a SecurityGroupRule
func (c *CloudClient) translateRuleProtocol(rule SecurityGroupRule) (vpcv1.SecurityGroupRulePrototypeIntf, error) {
	var remotePrototype vpcv1.SecurityGroupRuleRemotePrototypeIntf
	if len(rule.Remote) == 0 {
		return nil, fmt.Errorf("SecurityGroupRule is missing remote value")
	}
	remote, err := GetRemoteType(rule.Remote)
	if err != nil {
		return nil, err
	}

	if remote == ipType {
		remotePrototype = &vpcv1.SecurityGroupRuleRemotePrototypeIP{Address: &rule.Remote}
	} else { // CIDR
		remotePrototype = &vpcv1.SecurityGroupRuleRemotePrototypeCIDR{CIDRBlock: &rule.Remote}
	}

	direction := getEgressDirection(rule.Egress)
	var prototype vpcv1.SecurityGroupRulePrototypeIntf
	switch rule.Protocol {
	case "all":
		prototype = &vpcv1.SecurityGroupRulePrototypeSecurityGroupRuleProtocolAll{
			Direction: direction,
			Protocol:  core.StringPtr("all"),
			Remote:    remotePrototype,
		}
	case "tcp", "udp":
		if rule.PortMin == -1 && rule.PortMax == -1 {
			prototype = &vpcv1.SecurityGroupRulePrototypeSecurityGroupRuleProtocolTcpudp{
				Direction: direction,
				Protocol:  &rule.Protocol,
				Remote:    remotePrototype,
			}
		} else {
			prototype = &vpcv1.SecurityGroupRulePrototypeSecurityGroupRuleProtocolTcpudp{
				Direction: direction,
				Protocol:  &rule.Protocol,
				PortMin:   &rule.PortMin,
				PortMax:   &rule.PortMax,
				Remote:    remotePrototype,
			}
		}
	case "icmp":
		// NOTE paraglider permitlist rule doesn't support ICMP with specific codes and types
		if rule.IcmpType != -1 || rule.IcmpCode != -1 {
			return nil, fmt.Errorf(`paraglider permitlist rule doesn't support 
				icmp with specific codes and types`)
		}
		prototype = &vpcv1.SecurityGroupRulePrototypeSecurityGroupRuleProtocolIcmp{
			Direction: direction,
			Protocol:  core.StringPtr("icmp"),
			Remote:    remotePrototype,
		}
	}

	return prototype, nil
}

// Adds rule represented by the SecurityGroupRule object to its security group
func (c *CloudClient) UpdateSecurityGroupRule(rule SecurityGroupRule) error {
	prototype, err := c.translateRuleProtocol(rule)
	if err != nil {
		return err
	}
	var patchMap map[string]interface{}
	jsonVersion, err := json.Marshal(&prototype)
	if err != nil {
		return err
	}
	err = json.Unmarshal(jsonVersion, &patchMap)
	if err != nil {
		return err
	}
	return c.updateSecurityGroupRule(rule.SgID, rule.ID, patchMap)
}

func (c *CloudClient) updateSecurityGroupRule(sgID string, ruleID string, patch map[string]interface{}) error {

	options := vpcv1.UpdateSecurityGroupRuleOptions{
		SecurityGroupID:        &sgID,
		ID:                     &ruleID,
		SecurityGroupRulePatch: patch,
	}
	_, _, err := c.vpcService.UpdateSecurityGroupRule(&options)
	return err
}

// DeleteSecurityGroupRule deletes a rule from the security group
func (c *CloudClient) DeleteSecurityGroupRule(sgID, ruleID string) error {
	options := vpcv1.DeleteSecurityGroupRuleOptions{
		SecurityGroupID: &sgID,
		ID:              &ruleID,
	}
	_, err := c.vpcService.DeleteSecurityGroupRule(&options)
	return err
}

// IsRemoteInCIDR returns true if remote is contained in the CIDR's IP range.
// remote could be either an IP or a CIDR block.
func IsRemoteInCIDR(remote, cidr string) (bool, error) {
	remoteType, err := GetRemoteType(remote)
	if err != nil {
		return false, err
	}
	if remoteType == ipType {
		_, netCidr, err := net.ParseCIDR(cidr)
		if err != nil {
			return false, err
		}
		netIP := net.ParseIP(remote)
		if netIP == nil {
			return false, fmt.Errorf("ip %v isn't a valid IP address", remote)
		}
		return netCidr.Contains(netIP), nil
	}
	return utils.IsCIDRSubset(remote, cidr)
}

// GetRemoteType returns IBM specific keyword returned by vpc1 SDK,
// indicating the type of remote an SG rule permits
func GetRemoteType(remote string) (string, error) {
	ip := net.ParseIP(remote)
	if ip != nil {
		return ipType, nil
	}
	_, _, err := net.ParseCIDR(remote)
	if err == nil {
		return cidrType, nil
	}
	return "", fmt.Errorf("remote %v isn't an IP/CIDR", remote)
}

// returns IBM specific keyword returned by vpc1 SDK,
// indicating the traffic direction an SG rule permits
func getEgressDirection(egress bool) *string {
	if egress {
		return core.StringPtr(outboundType)
	} else {
		return core.StringPtr(inboundType)
	}
}

// return the specified rules without duplicates, while keeping the rules' hash values updated for future use.
func (c *CloudClient) GetUniqueSGRules(rules []SecurityGroupRule, rulesHashValues map[uint64]bool) ([]SecurityGroupRule, error) {
	var res []SecurityGroupRule
	for _, rule := range rules {
		// exclude unique field "ID" from hash calculation.
		ruleHashValue, err := ibmCommon.GetStructHash(rule, []string{"ID"})
		if err != nil {
			return nil, err
		}
		if _, ruleExists := rulesHashValues[ruleHashValue]; !ruleExists {
			res = append(res, rule)
			rulesHashValues[ruleHashValue] = true
		}
	}
	return res, nil
}

// return IDs of rules matching the specified specifications.
func (c *CloudClient) GetRulesIDs(rules []SecurityGroupRule, sgID string) ([]string, error) {
	var rulesIDs []string
	sgRules, err := c.GetSecurityRulesOfSG(sgID)
	if err != nil {
		return nil, err
	}
	for _, sgRule := range sgRules {
		for _, rule := range rules {
			// aggregate rules matching the specified rules, based on all fields except their IDs and SG IDs.
			if ibmCommon.AreStructsEqual(rule, sgRule, []string{"ID", "SgID"}) {
				rulesIDs = append(rulesIDs, sgRule.ID)
				// found matching rule, continue to the next sgRule
				break
			}
		}
	}
	return rulesIDs, nil
}

func (c *CloudClient) getIBMRuleID(ibmRule vpcv1.SecurityGroupRuleIntf) string {
	switch rule := ibmRule.(type) {
	case *vpcv1.SecurityGroupRule:
		return *rule.ID
	case *vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolAll:
		return *rule.ID
	case *vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp:
		return *rule.ID
	case *vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp:
		return *rule.ID
	}
	return ""
}

// returns rules in paraglider format from IBM cloud format
// TODO @cohen-j-omer: handle permitList tags if required.
func IBMToParagliderRules(rules []SecurityGroupRule) ([]*paragliderpb.PermitListRule, error) {
	var paragliderRules []*paragliderpb.PermitListRule

	for _, rule := range rules {
		if rule.PortMin != rule.PortMax {
			return nil, fmt.Errorf("SG rules with port ranges aren't currently supported")
		}
		// PortMin=PortMax since port ranges aren't supported.
		// srcPort=dstPort since ibm security rules are stateful,
		// i.e. they automatically also permit the reverse traffic.
		srcPort, dstPort := rule.PortMin, rule.PortMin

		permitListRule := &paragliderpb.PermitListRule{
			Targets:   []string{rule.Remote},
			Name:      rule.ID,
			Direction: ibmToParagliderDirection[rule.Egress],
			SrcPort:   int32(srcPort),
			DstPort:   int32(dstPort),
			Protocol:  ibmToParagliderProtocol[rule.Protocol],
		}
		paragliderRules = append(paragliderRules, permitListRule)

	}
	return paragliderRules, nil
}

// returns IBM SecurityGroupRule, converted from specified paraglider rule
// NOTE: with the current PermitListRule we can't translate ICMP rules with specific type or code
func ParagliderToIBMRules(securityGroupID string, rules []*paragliderpb.PermitListRule) (
	[]SecurityGroupRule, error) {
	var sgRules []SecurityGroupRule
	for _, rule := range rules {
		if len(rule.Targets) == 0 {
			return nil, fmt.Errorf("PermitListRule is missing Tag value. Rule:%+v", rule)
		}
		for _, target := range rule.Targets {
			remote := target
			remoteType, err := GetRemoteType(remote)
			if err != nil {
				return nil, err
			}
			sgRule := SecurityGroupRule{
				ID:         rule.Name,
				SgID:       securityGroupID,
				Protocol:   paragliderToIBMprotocol[rule.Protocol],
				Remote:     remote,
				RemoteType: remoteType,
				PortMin:    int64(rule.SrcPort),
				PortMax:    int64(rule.SrcPort),
				Egress:     paragliderToIBMDirection[rule.Direction],
			}

			if rule.Protocol == 1 { // icmp rule
				// setting value to -1 to indicate that all codes and types are allowed.
				// non negative icmp values have meaning, which is not supported by paraglider.
				sgRule.IcmpType = -1
				sgRule.IcmpCode = -1
			}

			sgRules = append(sgRules, sgRule)
		}
	}
	return sgRules, nil
}

// returns rules in IBM cloud format to paraglider format
// NOTE: with the current PermitListRule we can't translate ICMP rules with specific type or code
func ParagliderToIBMRule(securityGroupID string, pgRule *paragliderpb.PermitListRule) (
	[]SecurityGroupRule, error) {

	if len(pgRule.Targets) == 0 {
		return nil, fmt.Errorf("PermitListRule is missing target value. Rule:%+v", pgRule)
	}
	sgRules := make([]SecurityGroupRule, len(pgRule.Targets))
	for i, target := range pgRule.Targets {
		remote := target
		remoteType, err := GetRemoteType(remote)
		if err != nil {
			return nil, err
		}
		sgRule := SecurityGroupRule{
			ID:         pgRule.Name,
			SgID:       securityGroupID,
			Protocol:   paragliderToIBMprotocol[pgRule.Protocol],
			Remote:     remote,
			RemoteType: remoteType,
			PortMin:    int64(pgRule.SrcPort),
			PortMax:    int64(pgRule.SrcPort),
			Egress:     paragliderToIBMDirection[pgRule.Direction],
		}

		if pgRule.Protocol == 1 { // icmp rule
			// setting value to -1 to indicate that all codes and types are allowed.
			// non negative icmp values have meaning, which is not supported by paraglider.
			sgRule.IcmpType = -1
			sgRule.IcmpCode = -1
		}
		sgRules[i] = sgRule
	}

	return sgRules, nil
}
