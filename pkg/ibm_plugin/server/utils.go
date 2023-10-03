package ibm

import (
	"encoding/json"
	"fmt"
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

func getResourceIDInfo(resourceID *invisinetspb.ResourceID) (ResourceIDInfo, error) {
	parts := strings.Split(resourceID.Id, "/")
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
		if *rule.PortMin != *rule.PortMax {
			return nil, fmt.Errorf("SG rules with port ranges aren't currently supported")
		}
		// PortMin=PortMax since port ranges aren't supported.
		// srcPort=dstPort since ibm security rules are stateful,
		// i.e. they automatically also permit the reverse traffic.
		srcPort, dstPort := *rule.PortMin, *rule.PortMin

		permitListRule := &invisinetspb.PermitListRule{
			Tag:       []string{*rule.Remote},
			Id:        *rule.ID,
			Direction: ibmToInvisinetsDirection[*rule.Egress],
			SrcPort:   int32(srcPort),
			DstPort:   int32(dstPort),
			Protocol:  ibmToInvisinetsProtocol[*rule.Protocol],
		}
		invisinetsRules = append(invisinetsRules, permitListRule)

	}
	return invisinetsRules, nil
}
