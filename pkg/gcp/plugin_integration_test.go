//go:build integration

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

package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/googleapi"
	"google.golang.org/protobuf/proto"
)

type teardownInfo struct {
	project            string
	ctx                context.Context
	insertInstanceReqs []*computepb.InsertInstanceRequest
}

// Cleans up any resources that were created
func teardownIntegrationTest(teardownInfo *teardownInfo) {
	// Delete VMs
	instancesClient, err := compute.NewInstancesRESTClient(teardownInfo.ctx)
	if err != nil {
		panic(fmt.Sprintf("Error while creating client (you may need to manually delete any resources that were created): %v", err))
	}
	for _, insertInstanceReq := range teardownInfo.insertInstanceReqs {
		deleteInstanceReq := &computepb.DeleteInstanceRequest{
			Project:  insertInstanceReq.Project,
			Zone:     insertInstanceReq.Zone,
			Instance: *insertInstanceReq.InstanceResource.Name,
		}
		deleteInstanceReqOp, err := instancesClient.Delete(teardownInfo.ctx, deleteInstanceReq)
		if err != nil {
			var e *googleapi.Error
			if ok := errors.As(err, &e); !ok || e.Code != http.StatusNotFound {
				// Ignore 404 errors since resource may not have been created due to an error while running the test
				panic(fmt.Sprintf("Error on delete instance request (you may need to manually delete any resources that were created): %v", err))
			}
		} else {
			err = deleteInstanceReqOp.Wait(teardownInfo.ctx)
			if err != nil {
				panic(fmt.Sprintf("Error while waiting on delete instance op (you may need to manually delete any resources that were created): %v", err))
			}
		}
	}

	// Delete subnetworks
	networksClient, err := compute.NewNetworksRESTClient(teardownInfo.ctx)
	if err != nil {
		panic(fmt.Sprintf("Error while creating networks client (you may need to manually delete any resources that were created): %v", err))
	}
	subnetworksClient, err := compute.NewSubnetworksRESTClient(teardownInfo.ctx)
	if err != nil {
		panic(fmt.Sprintf("Error while creating subnetworks client (you may need to manually delete any resources that were created): %v", err))
	}
	deletedSubnetworkRegions := map[string]bool{}
	for _, insertInstanceReq := range teardownInfo.insertInstanceReqs {
		region := insertInstanceReq.Zone[:strings.LastIndex(insertInstanceReq.Zone, "-")]
		if !deletedSubnetworkRegions[region] {
			deleteSubnetworkReq := &computepb.DeleteSubnetworkRequest{
				Project:    teardownInfo.project,
				Region:     region,
				Subnetwork: getGCPSubnetworkName(region),
			}
			deleteSubnetworkOp, err := subnetworksClient.Delete(teardownInfo.ctx, deleteSubnetworkReq)
			if err != nil {
				var e *googleapi.Error
				if ok := errors.As(err, &e); !ok || e.Code != http.StatusNotFound {
					// Ignore 404 errors since resource may not have been created due to an error while running the test
					panic(fmt.Sprintf("Error on delete subnetwork request (you may need to manually delete any resources that were created): %v", err))
				}
			} else {
				err = deleteSubnetworkOp.Wait(teardownInfo.ctx)
				if err != nil {
					panic(fmt.Sprintf("Error while waiting on delete subnetwork op (you may need to manually delete any resources that were created): %v", err))
				}
			}
			deletedSubnetworkRegions[region] = true
		}
	}

	// Delete firewalls
	getEffectiveFirewallsReq := &computepb.GetEffectiveFirewallsNetworkRequest{
		Project: teardownInfo.project,
		Network: vpcName,
	}
	getEffectiveFirewallsResp, err := networksClient.GetEffectiveFirewalls(teardownInfo.ctx, getEffectiveFirewallsReq)
	if err != nil {
		panic(fmt.Sprintf("Error while getting firewalls (you may need to manually delete any resources that were created): %v", err))
	}
	firewallsClient, err := compute.NewFirewallsRESTClient(teardownInfo.ctx)
	if err != nil {
		panic(fmt.Sprintf("Error while creating firewalls client (you may need to manually delete any resources that were created): %v", err))
	}
	for _, firewall := range getEffectiveFirewallsResp.Firewalls {
		deleteFirewallReq := &computepb.DeleteFirewallRequest{
			Firewall: *firewall.Name,
			Project:  teardownInfo.project,
		}
		deleteFirewallOp, err := firewallsClient.Delete(teardownInfo.ctx, deleteFirewallReq)
		if err != nil {
			var e *googleapi.Error
			if ok := errors.As(err, &e); !ok || e.Code != http.StatusNotFound {
				// Ignore 404 errors since resource may not have been created due to an error while running the test
				panic(fmt.Sprintf("Error on delete firewall request (you may need to manually delete any resources that were created): %v", err))
			}
		} else {
			err = deleteFirewallOp.Wait(teardownInfo.ctx)
			if err != nil {
				panic(fmt.Sprintf("Error while waiting on delete firewall op (you may need to manually delete any resources that were created): %v", err))
			}
		}
	}

	// Delete VPC
	deleteNetworkReq := &computepb.DeleteNetworkRequest{
		Project: teardownInfo.project,
		Network: vpcName,
	}
	deleteNetworkOp, err := networksClient.Delete(teardownInfo.ctx, deleteNetworkReq)
	if err != nil {
		var e *googleapi.Error
		if ok := errors.As(err, &e); !ok || e.Code != http.StatusNotFound {
			// Ignore 404 errors since resource may not have been created due to an error while running the test
			panic(fmt.Sprintf("Error on delete subnetwork request (you may need to manually delete any resources that were created): %v", err))
		}
	} else {
		err = deleteNetworkOp.Wait(teardownInfo.ctx)
		if err != nil {
			panic(fmt.Sprintf("Error while waiting on delete network op (you may need to manually delete any resources that were created): %v", err))
		}
	}
}

func TestIntegration(t *testing.T) {
	// Setup
	project := os.Getenv("INVISINETS_GCP_PROJECT")
	if project == "" {
		panic("INVISINETS_GCP_PROJECT must be set")
	}
	ctx := context.Background()
	s := &GCPPluginServer{}

	// Teardown
	teardownInfo := &teardownInfo{
		project:            project,
		ctx:                ctx,
		insertInstanceReqs: make([]*computepb.InsertInstanceRequest, 0),
	}
	defer teardownIntegrationTest(teardownInfo)

	// Disk setting to be used across VM creation
	var disks = []*computepb.AttachedDisk{
		{
			InitializeParams: &computepb.AttachedDiskInitializeParams{
				DiskSizeGb:  proto.Int64(10),
				SourceImage: proto.String("projects/debian-cloud/global/images/family/debian-10"),
			},
			AutoDelete: proto.Bool(true),
			Boot:       proto.Bool(true),
			Type:       proto.String(computepb.AttachedDisk_PERSISTENT.String()),
		},
	}

	// Create VM in a clean state (i.e. no VPC or subnet)
	insertInstanceReq1 := &computepb.InsertInstanceRequest{
		Project: project,
		Zone:    "us-west1-a",
		InstanceResource: &computepb.Instance{
			Name:        proto.String("vm-invisinets-test-1"),
			MachineType: proto.String("zones/us-west1-a/machineTypes/f1-micro"),
			Disks:       disks,
		},
	}
	teardownInfo.insertInstanceReqs = append(teardownInfo.insertInstanceReqs, insertInstanceReq1)
	insertInstanceReq1Bytes, err := json.Marshal(insertInstanceReq1)
	if err != nil {
		t.Fatal(err)
	}
	resourceDescription1 := &invisinetspb.ResourceDescription{
		Description:  insertInstanceReq1Bytes,
		AddressSpace: "10.162.162.0/24",
	}
	createResource1Resp, err := s.CreateResource(
		ctx,
		resourceDescription1,
	)
	require.NoError(t, err)
	require.NotNil(t, createResource1Resp)
	assert.True(t, createResource1Resp.Success)

	// Create VM in different region (i.e. requires new subnet to be created)
	insertInstanceReq2 := &computepb.InsertInstanceRequest{
		Project: project,
		Zone:    "us-east1-b",
		InstanceResource: &computepb.Instance{
			Name:        proto.String("vm-invisinets-test-2"),
			MachineType: proto.String("zones/us-east1-b/machineTypes/f1-micro"),
			Disks:       disks,
		},
	}
	teardownInfo.insertInstanceReqs = append(teardownInfo.insertInstanceReqs, insertInstanceReq2)
	insertInstanceReq2Bytes, err := json.Marshal(insertInstanceReq2)
	if err != nil {
		t.Fatal(err)
	}
	resourceDescription2 := &invisinetspb.ResourceDescription{
		Description:  insertInstanceReq2Bytes,
		AddressSpace: "10.162.168.0/24",
	}
	createResource2Resp, err := s.CreateResource(
		ctx,
		resourceDescription2,
	)
	require.NoError(t, err)
	require.NotNil(t, createResource2Resp)
	assert.True(t, createResource2Resp.Success)

	// Check VPC and subnetworks
	networksClient, err := compute.NewNetworksRESTClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	getNetworkReq := &computepb.GetNetworkRequest{
		Network: vpcName,
		Project: project,
	}
	getNetworkResp, err := networksClient.Get(ctx, getNetworkReq)
	require.NoError(t, err)
	require.NotNil(t, getNetworkResp)
	subnetworks := make([]string, len(getNetworkResp.Subnetworks))
	for i, subnetURL := range getNetworkResp.Subnetworks {
		subnetworks[i] = subnetURL[strings.LastIndex(subnetURL, "/")+1:]
	}
	assert.ElementsMatch(
		t,
		[]string{getGCPSubnetworkName("us-west1"), getGCPSubnetworkName("us-east1")},
		subnetworks,
	)

	resourceId := project + "/" + insertInstanceReq1.Zone + "/" + *insertInstanceReq1.InstanceResource.Name

	permitList := &invisinetspb.PermitList{
		AssociatedResource: resourceId,
		Rules: []*invisinetspb.PermitListRule{
			{
				Direction: invisinetspb.Direction_INBOUND,
				DstPort:   443,
				Protocol:  6,
				Tag:       []string{"10.162.162.0/24"},
			},
		},
	}
	addPermitListRulesResp, err := s.AddPermitListRules(ctx, permitList)
	require.NoError(t, err)
	require.NotNil(t, addPermitListRulesResp)
	assert.True(t, addPermitListRulesResp.Success)

	getPermitListAfterAddResp, err := s.GetPermitList(ctx, &invisinetspb.ResourceID{Id: resourceId})
	require.NoError(t, err)
	require.NotNil(t, getPermitListAfterAddResp)
	assert.Equal(t, permitList.AssociatedResource, getPermitListAfterAddResp.AssociatedResource)
	assert.ElementsMatch(t, permitList.Rules, getPermitListAfterAddResp.Rules)

	deletePermitListRulesResp, err := s.DeletePermitListRules(ctx, permitList)
	require.NoError(t, err)
	require.NotNil(t, deletePermitListRulesResp)
	assert.True(t, deletePermitListRulesResp.Success)

	getPermitListAfterDeleteResp, err := s.GetPermitList(ctx, &invisinetspb.ResourceID{Id: resourceId})
	require.NoError(t, err)
	require.NotNil(t, getPermitListAfterDeleteResp)
	assert.Equal(t, permitList.AssociatedResource, getPermitListAfterDeleteResp.AssociatedResource)
	assert.Empty(t, getPermitListAfterDeleteResp.Rules)
}
