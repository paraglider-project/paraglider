package ibm

import (
	"encoding/json"
	"fmt"
	"strings"

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

func getResourceIDInfo(resourceID string) (ResourceIDInfo, error) {
	parts := strings.Split(resourceID, "/")
	if len(parts) < 5 {
		return ResourceIDInfo{}, fmt.Errorf("invalid resource ID format: expected at least 5 parts in the format of '/ResourceGroupID/{ResourceGroupID}/Region/{Region}/ResourceID/{ResourceID}...', got %d", len(parts))
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
