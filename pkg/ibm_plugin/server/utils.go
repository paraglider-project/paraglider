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

package ibm

import (
	"fmt"
	"hash/fnv"
	"reflect"
	"strings"

	"github.com/IBM/vpc-go-sdk/vpcv1"
	sdk "github.com/NetSys/invisinets/pkg/ibm_plugin/sdk"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
)

// ResourceIDInfo defines the necessary fields of a resource
type ResourceIDInfo struct {
	ResourceGroupID string `json:"ResourceGroupID"`
	Region          string `json:"Region"`
	ResourceID      string `json:"ResourceID"`
}

// mapping invisinets traffic directions to booleans
var invisinetsToIBMDirection = map[invisinetspb.Direction]bool{
	invisinetspb.Direction_OUTBOUND: true,
	invisinetspb.Direction_INBOUND:  false,
}

// mapping booleans invisinets traffic directions
var ibmToInvisinetsDirection = map[bool]invisinetspb.Direction{
	true:  invisinetspb.Direction_OUTBOUND,
	false: invisinetspb.Direction_INBOUND,
}

// mapping integers determined by the IANA standard to IBM protocols
var invisinetsToIBMprotocol = map[int32]string{
	-1: "all",
	1:  "icmp",
	6:  "tcp",
	17: "udp",
}

// mapping IBM protocols to integers determined by the IANA standard
var ibmToInvisinetsProtocol = map[string]int32{
	"all":  -1,
	"icmp": 1,
	"tcp":  6,
	"udp":  17,
}

// returns ResourceIDInfo out of an agreed upon formatted string:
// "/ResourceGroupID/{ResourceGroupID}/Region/{Region}/ResourceID/{ResourceID}"
func getResourceIDInfo(resourceID string) (ResourceIDInfo, error) {
	parts := strings.Split(resourceID, "/")
	if len(parts) < 5 {
		return ResourceIDInfo{}, fmt.Errorf("invalid resource ID format: expected at least 5 parts in the format of '/ResourceGroupID/{ResourceGroupID}/Region/{Region}/ResourceID/{ResourceID}', got %d", len(parts))
	}

	if parts[0] != "" || parts[1] != "ResourceGroupID" || parts[3] != "Region" {
		return ResourceIDInfo{}, fmt.Errorf("invalid resource ID format: expected '/ResourceGroupID/{ResourceGroupID}/Region/{Region}/ResourceID/{ResourceID}', got '%s'", resourceID)
	}

	info := ResourceIDInfo{
		ResourceGroupID: parts[2],
		Region:          parts[4],
		ResourceID:      parts[6],
	}

	return info, nil
}

func getZone(proto vpcv1.InstancePrototypeIntf) (string, error) {
	var zone vpcv1.ZoneIdentityIntf

	switch proto.(type) {
	case *vpcv1.InstancePrototypeInstanceByCatalogOffering:
		zone = proto.(*vpcv1.InstancePrototypeInstanceByCatalogOffering).Zone
	case *vpcv1.InstancePrototypeInstanceByImage:
		zone = proto.(*vpcv1.InstancePrototypeInstanceByImage).Zone
	case *vpcv1.InstancePrototypeInstanceBySourceSnapshot:
		zone = proto.(*vpcv1.InstancePrototypeInstanceBySourceSnapshot).Zone
	case *vpcv1.InstancePrototypeInstanceBySourceTemplate:
		zone = proto.(*vpcv1.InstancePrototypeInstanceBySourceTemplate).Zone
	case *vpcv1.InstancePrototypeInstanceByVolume:
		zone = proto.(*vpcv1.InstancePrototypeInstanceByVolume).Zone
	default:
		return "", fmt.Errorf("unable to determine time of InstancePrototype")
	}

	switch zone.(type) {
	case *vpcv1.ZoneIdentityByHref:
		href := zone.(*vpcv1.ZoneIdentityByHref).Href
		hrefZone := strings.Split(*href, "/")
		return hrefZone[len(hrefZone)-1], nil
	case *vpcv1.ZoneIdentityByName:
		return *zone.(*vpcv1.ZoneIdentityByName).Name, nil
	default:
		return "", fmt.Errorf("unable to determine time of ZoneIdentity")
	}
}

func ibmToInvisinetsRules(rules []sdk.SecurityGroupRule) ([]*invisinetspb.PermitListRule, error) {
	var invisinetsRules []*invisinetspb.PermitListRule

	for _, rule := range rules {
		if rule.PortMin != rule.PortMax {
			return nil, fmt.Errorf("SG rules with port ranges aren't currently supported")
		}
		// PortMin=PortMax since port ranges aren't supported.
		// srcPort=dstPort since ibm security rules are stateful,
		// i.e. they automatically also permit the reverse traffic.
		srcPort, dstPort := rule.PortMin, rule.PortMin

		permitListRule := &invisinetspb.PermitListRule{
			Targets:   []string{rule.Remote},
			Id:        rule.ID,
			Direction: ibmToInvisinetsDirection[rule.Egress],
			SrcPort:   int32(srcPort),
			DstPort:   int32(dstPort),
			Protocol:  ibmToInvisinetsProtocol[rule.Protocol],
		}
		invisinetsRules = append(invisinetsRules, permitListRule)

	}
	return invisinetsRules, nil
}

// Translate invisinets permit rules to SecurityGroupRule struct containing all IBM permit rules data
// NOTE: with the current PermitListRule we can't translate ICMP rules with specific type or code
func invisinetsToIBMRules(securityGroupID string, rules []*invisinetspb.PermitListRule) (
	[]sdk.SecurityGroupRule, error) {
	var sgRules []sdk.SecurityGroupRule
	for _, rule := range rules {
		if len(rule.Targets) == 0 {
			return nil, fmt.Errorf("PermitListRule is missing Tag value. Rule:%+v", rule)
		}
		for _, target := range rule.Targets {
			remote := target
			remoteType, err := sdk.GetRemoteType(remote)
			if err != nil {
				return nil, err
			}
			sgRule := sdk.SecurityGroupRule{
				ID:         rule.Id,
				SgID:       securityGroupID,
				Protocol:   invisinetsToIBMprotocol[rule.Protocol],
				Remote:     remote,
				RemoteType: remoteType,
				PortMin:    int64(rule.SrcPort),
				PortMax:    int64(rule.SrcPort),
				Egress:     invisinetsToIBMDirection[rule.Direction],
				// explicitly setting value to 0. other icmp values have meaning.
				IcmpType: 0,
				IcmpCode: 0,
			}
			sgRules = append(sgRules, sgRule)
		}
	}
	return sgRules, nil
}

// returns hash value of any struct containing primitives,
// or slices of primitives.
// fieldsToExclude contains field names to be excluded
// from hash calculation.
func getStructHash(s interface{}, fieldsToExclude []string) (uint64, error) {
	h := fnv.New64a()
	v := reflect.ValueOf(s)
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		fieldName := v.Type().Field(i).Name
		if sdk.DoesSliceContain(fieldsToExclude, fieldName) {
			// skip fields in fieldsToExclude from hash calculation
			continue
		}
		switch f.Kind() {
		case reflect.String:
			_, err := h.Write([]byte(f.String()))
			if err != nil {
				return 0, err
			}

		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			_, err := h.Write([]byte(fmt.Sprint(f.Int())))
			if err != nil {
				return 0, err
			}
		case reflect.Slice:
			for j := 0; j < f.Len(); j++ {
				_, err := h.Write([]byte(f.Index(j).String()))
				if err != nil {
					return 0, err
				}
			}
		}
	}
	return h.Sum64(), nil
}
