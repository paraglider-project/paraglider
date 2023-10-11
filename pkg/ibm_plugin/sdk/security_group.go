package ibm

import (
	"fmt"
	"net"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	utils "github.com/NetSys/invisinets/pkg/utils"
)

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

// creates security group in the specified VPC and tags it.
func (c *IBMCloudClient) createSecurityGroup(
	vpcID string) (*vpcv1.SecurityGroup, error) {
	sgTags := []string{vpcID}

	vpcIdentity := vpcv1.VPCIdentityByID{ID: &vpcID}
	sgName := GenerateResourceName("sg")
	options := vpcv1.CreateSecurityGroupOptions{
		VPC:           &vpcIdentity,
		ResourceGroup: c.resourceGroup,
		Name:          &sgName,
	}
	sg, _, err := c.vpcService.CreateSecurityGroup(&options)
	if err != nil {
		return nil, err
	}
	utils.Log.Printf("Created security group %v with id %v", sgName, *sg.ID)

	err = c.attachTag(sg.CRN, sgTags)
	if err != nil {
		utils.Log.Print("Failed to tag VPC with error:", err)
		return nil, err
	}
	return sg, nil
}

func (c *IBMCloudClient) GetSecurityRulesOfSG(sgID string) ([]SecurityGroupRule, error) {
	options := &vpcv1.ListSecurityGroupRulesOptions{}
	options.SetSecurityGroupID(sgID)
	rules, _, err := c.vpcService.ListSecurityGroupRules(options)
	if err != nil {
		return nil, err
	}
	return c.translateSecurityGroupRules(rules.Rules, sgID)
}

func (c *IBMCloudClient) translateSecurityGroupRules(
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

func (c *IBMCloudClient) translateSecurityGroupRule(
	ibmRule vpcv1.SecurityGroupRuleIntf, sgID string) (*SecurityGroupRule, error) {
	switch ibmRule.(type) {
	case *vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolAll:
		return c.translateSecurityGroupRuleGroupRuleProtocolAll(ibmRule, sgID)
	case *vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp:
		return c.translateSecurityGroupRuleGroupRuleProtocolIcmp(ibmRule, sgID)
	case *vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp:
		return c.translateSecurityGroupRuleGroupRuleProtocolTcpudp(ibmRule, sgID)
	}
	return nil, nil
}

func (c *IBMCloudClient) translateSecurityGroupRuleGroupRuleProtocolAll(
	ibmRule vpcv1.SecurityGroupRuleIntf, sgID string) (*SecurityGroupRule, error) {

	ibmRuleProtoAll := ibmRule.(*vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolAll)
	remote, remoteType, err := c.translateSecurityGroupRuleRemote(ibmRuleProtoAll.Remote)
	if err != nil {
		return nil, err
	}
	isEgress := false
	if *ibmRuleProtoAll.Direction == "outbound" {
		isEgress = true
	}
	rule := SecurityGroupRule{
		ID:         *ibmRuleProtoAll.ID,
		Protocol:   *ibmRuleProtoAll.Protocol,
		SgID:       sgID,
		Remote:     remote,
		RemoteType: remoteType,
		Egress:     isEgress,
		PortMin:    int64(-1),
		PortMax:    int64(-1),
	}
	return &rule, nil
}

func (c *IBMCloudClient) translateSecurityGroupRuleGroupRuleProtocolIcmp(
	ibmRule vpcv1.SecurityGroupRuleIntf, sgID string) (*SecurityGroupRule, error) {

	ibmRuleIcmp := ibmRule.(*vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp)
	remote, remoteType, err := c.translateSecurityGroupRuleRemote(ibmRuleIcmp.Remote)
	if err != nil {
		return nil, err
	}
	isEgress := false
	if *ibmRuleIcmp.Direction == "outbound" {
		isEgress = true
	}
	icmpCode := int64(-1)
	if ibmRuleIcmp.Code != nil {
		icmpCode = *ibmRuleIcmp.Code
	}
	icmpType := int64(-1)
	if ibmRuleIcmp.Type != nil {
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
	}
	return &rule, nil
}

func (c *IBMCloudClient) translateSecurityGroupRuleGroupRuleProtocolTcpudp(
	ibmRule vpcv1.SecurityGroupRuleIntf, sgID string) (*SecurityGroupRule, error) {

	ibmRuleTcpUdp := ibmRule.(*vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp)
	remote, remoteType, err := c.translateSecurityGroupRuleRemote(ibmRuleTcpUdp.Remote)
	if err != nil {
		return nil, err
	}
	isEgress := false
	if *ibmRuleTcpUdp.Direction == "outbound" {
		isEgress = true
	}
	rule := SecurityGroupRule{
		ID:         *ibmRuleTcpUdp.ID,
		Protocol:   *ibmRuleTcpUdp.Protocol,
		SgID:       sgID,
		Remote:     remote,
		RemoteType: remoteType,
		PortMin:    *ibmRuleTcpUdp.PortMin,
		PortMax:    *ibmRuleTcpUdp.PortMax,
		Egress:     isEgress,
	}
	return &rule, nil
}

func (c *IBMCloudClient) translateSecurityGroupRuleRemote(
	ibmRuleRemoteIntf vpcv1.SecurityGroupRuleRemoteIntf) (string, string, error) {

	switch v := ibmRuleRemoteIntf.(type) {
	// According to the docs, the interface should map to a specific type,
	// but in this case it seems to just map to a generic "remote" where pointers may be nil
	case *vpcv1.SecurityGroupRuleRemote:
		ibmRuleRemote := ibmRuleRemoteIntf.(*vpcv1.SecurityGroupRuleRemote)
		if ibmRuleRemote.Address != nil {
			return *ibmRuleRemote.Address, "IP", nil
		}
		if ibmRuleRemote.CIDRBlock != nil {
			return *ibmRuleRemote.CIDRBlock, "CIDR", nil
		}
		// For IBM Cloud, it is common to have an inbound rule accepting traffic
		// from a security group (sometimes the same where the rule belongs)
		if ibmRuleRemote.ID != nil {
			return *ibmRuleRemote.ID, "SG", nil
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

/*
The following functions are responsible for assigning SecurityGroupRules
to a security group.
*/
func (c *IBMCloudClient) AddSecurityGroupRule(rule SecurityGroupRule) error {
	var remotePrototype vpcv1.SecurityGroupRuleRemotePrototypeIntf
	if len(rule.Remote) == 0 {
		return fmt.Errorf("SecurityGroupRule is missing remote value")
	}
	remote, err := GetRemoteType(rule.Remote)
	if err != nil {
		return err
	}

	if remote == "IP" {
		remotePrototype = &vpcv1.SecurityGroupRuleRemotePrototypeIP{Address: &rule.Remote}
	} else { // CIDR
		remotePrototype = &vpcv1.SecurityGroupRuleRemotePrototypeCIDR{CIDRBlock: &rule.Remote}
	}

	// remotePrototype := &vpcv1.SecurityGroupRuleRemotePrototypeIP{Address: rule.Remote}
	direction := getEgressDirection(rule.Egress)
	switch rule.Protocol {
	case "all":
		return c.AddAnyProtoSecurityGroupRule(rule.SgID, remotePrototype, direction)
	case "tcp", "udp":
		return c.addTcpUdpSecurityGroupRule(rule.SgID, remotePrototype, rule.Protocol, rule.PortMin, rule.PortMax, direction)
	case "icmp":
		return c.addIcmpSecurityGroupRule(rule.SgID, remotePrototype, rule.IcmpType, rule.IcmpCode, direction)
	}
	return nil
}

func (c *IBMCloudClient) addTcpUdpSecurityGroupRule(
	sgID string,
	remotePrototype vpcv1.SecurityGroupRuleRemotePrototypeIntf,
	protocol string,
	portMin, portMax int64,
	direction *string,
) error {

	prototype := vpcv1.SecurityGroupRulePrototypeSecurityGroupRuleProtocolTcpudp{
		Direction: direction,
		Protocol:  &protocol,
		PortMin:   &portMin,
		PortMax:   &portMax,
		Remote:    remotePrototype,
	}
	return c.addSecurityGroupRule(sgID, &prototype)
}

func (c *IBMCloudClient) addIcmpSecurityGroupRule(
	sgID string,
	remotePrototype vpcv1.SecurityGroupRuleRemotePrototypeIntf,
	icmpType, icmpCode int64,
	direction *string,
) error {

	// In IBM Cloud, -1 is not accepted to signal "all types and codes", and
	// a nil pointer is used instead
	if icmpType != -1 && icmpCode != -1 {
		return fmt.Errorf(`invisinets PermitListRule doesn't support 
			icmp with specific codes/types.`)
	}

	// remote := vpcv1.SecurityGroupRuleRemotePrototypeCIDR{CIDRBlock: cidrBlock}
	prototype := vpcv1.SecurityGroupRulePrototypeSecurityGroupRuleProtocolIcmp{
		Direction: direction,
		Protocol:  core.StringPtr("icmp"),
		Type:      &icmpType,
		Code:      &icmpCode,
		Remote:    remotePrototype,
	}
	return c.addSecurityGroupRule(sgID, &prototype)
}

func (c *IBMCloudClient) AddAnyProtoSecurityGroupRule(
	sgID string,
	remotePrototype vpcv1.SecurityGroupRuleRemotePrototypeIntf,
	direction *string,
) error {
	prototype := vpcv1.SecurityGroupRulePrototypeSecurityGroupRuleProtocolAll{
		Direction: direction,
		Protocol:  core.StringPtr("all"),
		Remote:    remotePrototype,
	}
	return c.addSecurityGroupRule(sgID, &prototype)
}

func (c *IBMCloudClient) addSecurityGroupRule(
	sgID string,
	prototype vpcv1.SecurityGroupRulePrototypeIntf,
) error {

	options := vpcv1.CreateSecurityGroupRuleOptions{
		SecurityGroupID:            &sgID,
		SecurityGroupRulePrototype: prototype,
	}
	_, _, err := c.vpcService.CreateSecurityGroupRule(&options)
	return err
}

func (c *IBMCloudClient) DeleteSecurityGroupRule(
	sgID, ruleID string,
) error {
	options := vpcv1.DeleteSecurityGroupRuleOptions{
		SecurityGroupID: &sgID,
		ID:              &ruleID,
	}
	_, err := c.vpcService.DeleteSecurityGroupRule(&options)
	return err
}

// returns true if remote is contained in the CIDR's IP range.
// remote could be either an IP or a CIDR block.
func IsRemoteInCidr(remote, cidr string) (bool, error) {
	remoteType, err := GetRemoteType(remote)
	if err != nil {
		return false, err
	}
	if remoteType == "IP" {
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
	return IsCidrSubset(remote, cidr)
}

// returns IBM specific keyword returned by vpc1 SDK,
// indicating the type of remote an SG rule permits
func GetRemoteType(remote string) (string, error) {
	ip := net.ParseIP(remote)
	if ip != nil {
		return "IP", nil
	}
	_, _, err := net.ParseCIDR(remote)
	if err == nil {
		return "CIDR", nil
	}
	return "", fmt.Errorf("remote %v isn't a CIDR/IP", remote)
}

// returns IBM specific keyword returned by vpc1 SDK,
// indicating the traffic direction an SG rule permits
func getEgressDirection(egress bool) *string {
	if egress {
		return core.StringPtr("outbound")
	} else {
		return core.StringPtr("inbound")
	}
}
