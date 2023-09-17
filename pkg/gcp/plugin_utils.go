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
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/googleapi"
	"google.golang.org/protobuf/proto"
)

type GcpTestTeardownInfo struct {
	Project            string
	InsertInstanceReqs []*computepb.InsertInstanceRequest
}

func GetGcpProject() string {
	project := os.Getenv("INVISINETS_GCP_PROJECT")
	if project == "" {
		panic("INVISINETS_GCP_PROJECT must be set")
	}
	return project
}

// Cleans up any resources that were created
// If you got a panic while the tests ran, you may need to manually clean up resources, which is most easily done through the console.
// 1. Delete VMs (https://cloud.google.com/compute/docs/instances/deleting-instance).
// 2. Delete VPC (https://cloud.google.com/vpc/docs/create-modify-vpc-networks#deleting_a_network). Doing this in the console should delete any associated firewalls and subnets.
func TeardownGcpTesting(teardownInfo *GcpTestTeardownInfo) {
	// Delete VMs
	instancesClient, err := compute.NewInstancesRESTClient(context.Background())
	if err != nil {
		panic(fmt.Sprintf("Error while creating client (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
	}
	for _, insertInstanceReq := range teardownInfo.InsertInstanceReqs {
		deleteInstanceReq := &computepb.DeleteInstanceRequest{
			Project:  insertInstanceReq.Project,
			Zone:     insertInstanceReq.Zone,
			Instance: *insertInstanceReq.InstanceResource.Name,
		}
		deleteInstanceReqOp, err := instancesClient.Delete(context.Background(), deleteInstanceReq)
		if err != nil {
			var e *googleapi.Error
			if ok := errors.As(err, &e); !ok || e.Code != http.StatusNotFound {
				// Ignore 404 errors since resource may not have been created due to an error while running the test
				panic(fmt.Sprintf("Error on delete instance request (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
			}
		} else {
			err = deleteInstanceReqOp.Wait(context.Background())
			if err != nil {
				panic(fmt.Sprintf("Error while waiting on delete instance op (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
			}
		}
	}

	// Delete subnetworks
	networksClient, err := compute.NewNetworksRESTClient(context.Background())
	if err != nil {
		panic(fmt.Sprintf("Error while creating networks client (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
	}
	subnetworksClient, err := compute.NewSubnetworksRESTClient(context.Background())
	if err != nil {
		panic(fmt.Sprintf("Error while creating subnetworks client (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
	}
	deletedSubnetworkRegions := map[string]bool{}
	for _, insertInstanceReq := range teardownInfo.InsertInstanceReqs {
		region := insertInstanceReq.Zone[:strings.LastIndex(insertInstanceReq.Zone, "-")]
		if !deletedSubnetworkRegions[region] {
			deleteSubnetworkReq := &computepb.DeleteSubnetworkRequest{
				Project:    teardownInfo.Project,
				Region:     region,
				Subnetwork: getGCPSubnetworkName(region),
			}
			deleteSubnetworkOp, err := subnetworksClient.Delete(context.Background(), deleteSubnetworkReq)
			if err != nil {
				var e *googleapi.Error
				if ok := errors.As(err, &e); !ok || e.Code != http.StatusNotFound {
					// Ignore 404 errors since resource may not have been created due to an error while running the test
					panic(fmt.Sprintf("Error on delete subnetwork request (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
				}
			} else {
				err = deleteSubnetworkOp.Wait(context.Background())
				if err != nil {
					panic(fmt.Sprintf("Error while waiting on delete subnetwork op (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
				}
			}
			deletedSubnetworkRegions[region] = true
		}
	}

	// Delete firewalls
	getEffectiveFirewallsReq := &computepb.GetEffectiveFirewallsNetworkRequest{
		Project: teardownInfo.Project,
		Network: vpcName,
	}
	getEffectiveFirewallsResp, err := networksClient.GetEffectiveFirewalls(context.Background(), getEffectiveFirewallsReq)
	if err != nil {
		panic(fmt.Sprintf("Error while getting firewalls (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
	}
	firewallsClient, err := compute.NewFirewallsRESTClient(context.Background())
	if err != nil {
		panic(fmt.Sprintf("Error while creating firewalls client (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
	}
	for _, firewall := range getEffectiveFirewallsResp.Firewalls {
		deleteFirewallReq := &computepb.DeleteFirewallRequest{
			Firewall: *firewall.Name,
			Project:  teardownInfo.Project,
		}
		deleteFirewallOp, err := firewallsClient.Delete(context.Background(), deleteFirewallReq)
		if err != nil {
			var e *googleapi.Error
			if ok := errors.As(err, &e); !ok || e.Code != http.StatusNotFound {
				// Ignore 404 errors since resource may not have been created due to an error while running the test
				panic(fmt.Sprintf("Error on delete firewall request (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
			}
		} else {
			err = deleteFirewallOp.Wait(context.Background())
			if err != nil {
				panic(fmt.Sprintf("Error while waiting on delete firewall op (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
			}
		}
	}

	// TODO @seankimkdy: delete all VPN related resources

	// Delete VPC
	deleteNetworkReq := &computepb.DeleteNetworkRequest{
		Project: teardownInfo.Project,
		Network: vpcName,
	}
	deleteNetworkOp, err := networksClient.Delete(context.Background(), deleteNetworkReq)
	if err != nil {
		var e *googleapi.Error
		if ok := errors.As(err, &e); !ok || e.Code != http.StatusNotFound {
			// Ignore 404 errors since resource may not have been created due to an error while running the test
			panic(fmt.Sprintf("Error on delete subnetwork request (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
		}
	} else {
		err = deleteNetworkOp.Wait(context.Background())
		if err != nil {
			panic(fmt.Sprintf("Error while waiting on delete network op (see docstring of teardownIntegrationTest on how to manually delete resources): %v", err))
		}
	}
}

// TODO @seankimkdy: change existing integation test to use this method
func GetTestVmParameters(project string, name string, zone string) *computepb.InsertInstanceRequest {
	return &computepb.InsertInstanceRequest{
		Project: project,
		Zone:    zone,
		InstanceResource: &computepb.Instance{
			Name:        proto.String(name),
			MachineType: proto.String("zones/" + zone + "/machineTypes/f1-micro"),
			Disks: []*computepb.AttachedDisk{
				{
					InitializeParams: &computepb.AttachedDiskInitializeParams{
						DiskSizeGb:  proto.Int64(10),
						SourceImage: proto.String("projects/debian-cloud/global/images/family/debian-10"),
					},
					AutoDelete: proto.Bool(true),
					Boot:       proto.Bool(true),
					Type:       proto.String(computepb.AttachedDisk_PERSISTENT.String()),
				},
			},
		},
	}
}
