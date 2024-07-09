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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	billing "cloud.google.com/go/billing/apiv1"
	billingpb "cloud.google.com/go/billing/apiv1/billingpb"
	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	networkmanagement "cloud.google.com/go/networkmanagement/apiv1"
	networkmanagementpb "cloud.google.com/go/networkmanagement/apiv1/networkmanagementpb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	resourcemanagerpb "cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	serviceusage "cloud.google.com/go/serviceusage/apiv1"
	"cloud.google.com/go/serviceusage/apiv1/serviceusagepb"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/googleapi"
	"google.golang.org/protobuf/proto"
)

const (
	computeUrlPrefix   = "https://www.googleapis.com/compute/v1/"
	containerUrlPrefix = "https://container.googleapis.com/v1beta1/"
)

var urlPrefixes = []string{computeUrlPrefix, containerUrlPrefix}

func generateProjectId(testName string) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	const projectIdMaxLength = 30
	prefix := "pg-" + testName
	var suffix string
	if os.Getenv("GH_RUN_ID") != "" {
		// Use run ID as part of the project ID since run number can reset after a workflow changes, meaning it could result in duplicate project IDs which GCP doesn't allow (even after deletion).
		// Run attempt is also included since run ID does not reset on re-runs.
		suffix = hash(os.Getenv("GH_RUN_ID"), os.Getenv("GH_RUN_ATTEMPT"))
	} else {
		key := make([]byte, projectIdMaxLength)
		_, err := rand.Read(key)
		if err != nil {
			panic(fmt.Errorf("could not generate random bytes: %w", err))
		}
		for i, v := range key {
			key[i] = charset[v%byte(len(charset))]
		}
		suffix = string(key)
	}
	return (prefix + "-" + suffix)[:projectIdMaxLength]
}

func SetupGcpTesting(testName string) string {
	var projectId string
	if os.Getenv("INVISINETS_GCP_PROJECT") != "" {
		projectId = os.Getenv("INVISINETS_GCP_PROJECT")
	} else {
		var projectDisplayName string
		projectId = generateProjectId(testName)
		if os.Getenv("GH_RUN_NUMBER") != "" {
			// Use run number in project display name since it's more human readable
			projectDisplayName = fmt.Sprintf("paraglider-gh-%s-%s", os.Getenv("GH_RUN_NUMBER"), testName)
		} else {
			projectDisplayName = projectId
		}
		ctx := context.Background()
		projectsClient, err := resourcemanager.NewProjectsClient(ctx)
		if err != nil {
			panic(fmt.Errorf("unable to create projects client: %w", err))
		}
		// Create project
		createProjectReq := &resourcemanagerpb.CreateProjectRequest{
			Project: &resourcemanagerpb.Project{
				ProjectId:   projectId,
				DisplayName: projectDisplayName,
				Parent:      os.Getenv("PARAGLIDER_GCP_PROJECT_PARENT"),
			},
		}
		createProjectOp, err := projectsClient.CreateProject(ctx, createProjectReq)
		if err != nil {
			panic(fmt.Errorf("unable to create project: %w", err))
		}
		_, err = createProjectOp.Wait(ctx)
		if err != nil {
			panic(fmt.Errorf("unable to wait on create project op: %w", err))
		}

		// Enable billing
		cloudBillingClient, err := billing.NewCloudBillingRESTClient(ctx)
		if err != nil {
			panic(fmt.Errorf("unable to create cloud billing client: %w", err))
		}
		updateProjectBillingInfoReq := &billingpb.UpdateProjectBillingInfoRequest{
			Name: "projects/" + projectId,
			ProjectBillingInfo: &billingpb.ProjectBillingInfo{
				BillingAccountName: os.Getenv("INVISINETS_GCP_PROJECT_BILLING_ACCOUNT_NAME"),
			},
		}
		_, err = cloudBillingClient.UpdateProjectBillingInfo(ctx, updateProjectBillingInfoReq)
		if err != nil {
			panic(fmt.Errorf("unable to update project billing info: %w", err))
		}

		// Enable necessary API services
		serviceUsageClient, err := serviceusage.NewClient(ctx) // Can't use REST client for some reason (filed as bug within Google internally)
		if err != nil {
			panic(fmt.Errorf("unable to create serviceusage client: %w", err))
		}
		batchEnableServicesReq := &serviceusagepb.BatchEnableServicesRequest{
			Parent:     "projects/" + projectId,
			ServiceIds: []string{"cloudbilling.googleapis.com", "compute.googleapis.com", "networkmanagement.googleapis.com"},
		}
		batchEnableServicesOp, err := serviceUsageClient.BatchEnableServices(ctx, batchEnableServicesReq)
		if err != nil {
			panic(fmt.Errorf("unable to batch enable services: %w", err))
		}
		_, err = batchEnableServicesOp.Wait(ctx)
		if err != nil {
			panic(fmt.Errorf("unable to wait on batch enable services op: %w", err))
		}
	}
	return projectId
}

func TeardownGcpTesting(projectId string) {
	if projectId != os.Getenv("INVISINETS_GCP_PROJECT") && os.Getenv("INVISINETS_TEST_PERSIST") != "1" {
		ctx := context.Background()
		projectsClient, err := resourcemanager.NewProjectsClient(ctx)
		if err != nil {
			panic(fmt.Errorf("unable to create projects client: %w", err))
		}
		deleteProjectReq := &resourcemanagerpb.DeleteProjectRequest{
			Name: "projects/" + projectId,
		}
		deleteProjectOp, err := projectsClient.DeleteProject(ctx, deleteProjectReq)
		if err != nil {
			panic(fmt.Errorf("unable to delete project: %w", err))
		}
		_, err = deleteProjectOp.Wait(ctx)
		if err != nil {
			panic(fmt.Errorf("unable to wait on delete project op: %w", err))
		}
	}
}

func GetTestVmParameters(project string, zone string, name string) *computepb.InsertInstanceRequest {
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

func GetInstanceIpAddress(project string, zone string, instanceName string) (string, error) {
	ctx := context.Background()
	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return "", fmt.Errorf("NewInstancesRESTClient: %w", err)
	}
	getInstanceReq := &computepb.GetInstanceRequest{
		Instance: instanceName,
		Project:  project,
		Zone:     zone,
	}
	instance, err := instancesClient.Get(ctx, getInstanceReq)
	if err != nil {
		return "", fmt.Errorf("unable to get instance: %w", err)
	}
	return *instance.NetworkInterfaces[0].NetworkIP, nil
}

func GetInstanceId(project string, zone string, instanceName string) (uint64, error) {
	ctx := context.Background()
	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return 0, fmt.Errorf("NewInstancesRESTClient: %w", err)
	}
	getInstanceReq := &computepb.GetInstanceRequest{
		Instance: instanceName,
		Project:  project,
		Zone:     zone,
	}
	instance, err := instancesClient.Get(ctx, getInstanceReq)
	if err != nil {
		return 0, fmt.Errorf("unable to get instance: %w", err)
	}
	return *instance.Id, nil
}

// Runs connectivity test between two endpoints
func RunPingConnectivityTest(t *testing.T, project string, name string, srcEndpoint *networkmanagementpb.Endpoint, dstEndpoint *networkmanagementpb.Endpoint) {
	ctx := context.Background()
	reachabilityClient, err := networkmanagement.NewReachabilityClient(ctx) // Can't use REST client for some reason (filed as bug within Google internally)
	if err != nil {
		t.Fatal(err)
	}
	connectivityTestId := "connectivity-test-" + name
	createConnectivityTestReq := &networkmanagementpb.CreateConnectivityTestRequest{
		Parent: "projects/" + project + "/locations/global",
		TestId: connectivityTestId,
		Resource: &networkmanagementpb.ConnectivityTest{
			Name:        "projects/" + project + "/locations/global/connectivityTests" + connectivityTestId,
			Protocol:    "ICMP",
			Source:      srcEndpoint,
			Destination: dstEndpoint,
		},
	}
	createConnectivityTestOp, err := reachabilityClient.CreateConnectivityTest(ctx, createConnectivityTestReq)
	if err != nil {
		t.Fatal(err)
	}
	connectivityTest, err := createConnectivityTestOp.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}

	reachable := connectivityTest.ReachabilityDetails.Result == networkmanagementpb.ReachabilityDetails_REACHABLE
	// Retry up to five times
	for i := 0; i < 5 && !reachable; i++ {
		rerunConnectivityReq := &networkmanagementpb.RerunConnectivityTestRequest{
			Name: connectivityTest.Name,
		}
		rerunConnectivityTestOp, err := reachabilityClient.RerunConnectivityTest(ctx, rerunConnectivityReq)
		if err != nil {
			t.Fatal(err)
		}
		connectivityTest, err = rerunConnectivityTestOp.Wait(ctx)
		if err != nil {
			t.Fatal(err)
		}
		reachable = connectivityTest.ReachabilityDetails.Result == networkmanagementpb.ReachabilityDetails_REACHABLE
	}

	require.True(t, reachable)
}

// GCP naming conventions
const (
	paragliderPrefix = "para"
)

// Hashes values to lowercase hex string for use in naming GCP resources
func hash(values ...string) string {
	hash := sha256.Sum256([]byte(strings.Join(values, "")))
	return strings.ToLower(hex.EncodeToString(hash[:]))
}

/* --- RESOURCE NAME --- */

func getParagliderNamespacePrefix(namespace string) string {
	return paragliderPrefix + "-" + namespace
}

func getRegionFromZone(zone string) string {
	return zone[:strings.LastIndex(zone, "-")]
}

// parseUrl parses fully qualified and partial GCP resource URLs into a map of URL components (e.g., region)
// and their corresponding values (e.g., us-west1).
func parseUrl(url string) map[string]string {
	path := url
	for _, urlPrefix := range urlPrefixes {
		path = strings.TrimPrefix(path, urlPrefix)
	}
	parsedUrl := map[string]string{}
	pathComponents := strings.Split(path, "/")
	for i := 0; i < len(pathComponents)-1; {
		if pathComponents[i] == "global" {
			// Global resources only have a "global" specification without a trailing value
			// (e.g., projects/invisinets/global/networks/default)
			i += 1
		} else {
			parsedUrl[pathComponents[i]] = pathComponents[i+1]
			i += 2
		}
	}
	return parsedUrl
}

// Checks if GCP error response is a not found error
func isErrorNotFound(err error) bool {
	var e *googleapi.Error
	ok := errors.As(err, &e)
	return ok && e.Code == http.StatusNotFound
}

// Checks if GCP error response is a duplicate error
func isErrorDuplicate(err error) bool {
	var e *googleapi.Error
	ok := errors.As(err, &e)
	return ok && e.Code == http.StatusConflict
}
