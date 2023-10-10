package ibm

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"reflect"
	"strings"

	sdk "github.com/NetSys/invisinets/pkg/ibm_plugin/sdk"
	logger "github.com/NetSys/invisinets/pkg/logger"

	"github.com/NetSys/invisinets/pkg/invisinetspb"
)

type ResourceIDInfo struct {
	ResourceGroupID string `json:"ResourceGroupID"`
	Region          string `json:"Region"`
	ResourceID      string `json:"ResourceID"`
}

// InstanceFields is a temporary solution until invisinetspb.ResourceDescription.Description
// will be replaced with a concrete type.
type InstanceData struct {
	Profile string `json:"profile"` // optional
	Zone    string `json:"zone"`
	Name    string `json:"name"` // optional
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

func getInstanceData(resourceDesc *invisinetspb.ResourceDescription) (InstanceData, error) {
	vmFields := InstanceData{}

	err := json.Unmarshal(resourceDesc.Description, &vmFields)
	if err != nil {
		return InstanceData{}, fmt.Errorf("failed to unmarshal resource description:%+v", err)
	}
	if vmFields.Zone == "" {
		logger.Log.Println("Missing mandatory field: 'zone' to launch a VM")
		return InstanceData{}, err
	}
	return vmFields, nil
}

func sgRules2InvisinetsRules(rules []sdk.SecurityGroupRule) ([]*invisinetspb.PermitListRule, error) {
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
			Tag:       []string{rule.Remote},
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
func invisinetsRules2IbmRules(securityGroupID string, rules []*invisinetspb.PermitListRule) (
	[]sdk.SecurityGroupRule, error) {
	var sgRules []sdk.SecurityGroupRule
	for _, rule := range rules {
		if len(rule.Tag) == 0 {
			return nil, fmt.Errorf("PermitListRule is missing Tag value")
		}
		remote := rule.Tag[0]
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
			IcmpType:   0,
			IcmpCode:   0,
		}
		sgRules = append(sgRules, sgRule)
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
