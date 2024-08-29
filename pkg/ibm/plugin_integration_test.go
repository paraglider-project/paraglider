//go:build integration

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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/paraglider-project/paraglider/pkg/kvstore"
	"github.com/paraglider-project/paraglider/pkg/orchestrator"
	"github.com/paraglider-project/paraglider/pkg/orchestrator/config"
	"github.com/paraglider-project/paraglider/pkg/paragliderpb"
	tagging "github.com/paraglider-project/paraglider/pkg/tag_service"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
	"github.com/stretchr/testify/require"
)

var testDeployment, resourceGroupID string // IBM test variables
var testResourceIDUSEast1 string
var testResourceIDUSEast2 string
var testResourceIDUSEast3 string
var testResourceIDEUDE1 string
var testResourceIDUSSouth1 string

const (
	testUSEastRegion         = "us-east"
	testUSSouthRegion        = "us-south"
	testEURegion             = "eu-de"
	testZoneUSEast1          = testUSEastRegion + "-1"
	testZoneUSEast2          = testUSEastRegion + "-2"
	testZoneUSEast3          = testUSEastRegion + "-3"
	testZoneUSSouth1         = testUSSouthRegion + "-1"
	testZoneEUDE1            = testEURegion + "-1"
	testInstanceNameUSEast1  = "pg-vm-east-1"
	testInstanceNameUSEast2  = "pg-vm-east-2"
	testInstanceNameUSEast3  = "pg-vm-east-3"
	testInstanceNameUSSouth1 = "pg-vm-south-1"
	testInstanceNameEUDE1    = "pg-vm-de-1"

	testImageUSEast  = "r014-0acbdcb5-a68f-4a52-98ea-4da4fe89bacb" // us-east Ubuntu 22.04
	testImageEUDE    = "r010-f68ef7b3-1c5e-4ef7-8040-7ae0f5bf04fd" // eu-de Ubuntu 22.04
	testImageUSSouth = "r006-01deb923-46f6-44c3-8fdc-99d8493d2464" // us-south Ubuntu 22.04
	testProfile      = "bx2-2x8"
	testNamespace    = "paraglider-namespace"
)

// permit list to test connectivity via pings. Made to test Transit and VPN gateways configurations
var pingTestPermitList []*paragliderpb.PermitListRule = []*paragliderpb.PermitListRule{
	//ICMP protocol rule to accept pings
	{
		Name:      "inboundICMP",
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   -1,
		DstPort:   -1,
		Protocol:  1,
		Targets:   []string{"10.0.0.1"},
	},
	// ssh to accept ssh connection
	{
		Name:      "inboundSSH",
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   22,
		DstPort:   22,
		Protocol:  6,
		Targets:   []string{"10.0.0.1"},
	},
	//All protocol to allow all egress traffic
	{
		Name:      "outboundALL",
		Direction: paragliderpb.Direction_OUTBOUND,
		SrcPort:   -1,
		DstPort:   -1,
		Protocol:  -1,
		Targets:   []string{"10.0.0.1"},
	},
}

func TestMain(m *testing.M) {
	flag.Parse()
	resourceGroupID = GetIBMResourceGroupID()
	testResourceIDUSEast1 = "/resourcegroup/" + resourceGroupID + "/zone/" + testZoneUSEast1 + "/instance/"
	testResourceIDUSEast2 = "/resourcegroup/" + resourceGroupID + "/zone/" + testZoneUSEast2 + "/instance/"
	testResourceIDUSEast3 = "/resourcegroup/" + resourceGroupID + "/zone/" + testZoneUSEast3 + "/instance/"
	testResourceIDEUDE1 = "/resourcegroup/" + resourceGroupID + "/zone/" + testZoneEUDE1 + "/instance/"
	testResourceIDUSSouth1 = "/resourcegroup/" + resourceGroupID + "/zone/" + testZoneUSSouth1 + "/instance/"
	testDeployment = "/resourcegroup/" + resourceGroupID
	exitCode := m.Run()
	os.Exit(exitCode)
}

// TODO(cohen-j-omer) will add verification for number of rules
// usage: go test --tags=integration -run TestAddPermitRulesIntegration -timeout 0
// -timeout 0 removes limit of 10 min. runtime, which is necessary due to long deployment time of Azure's VPN.
func TestAddPermitRulesIntegration(t *testing.T) {
	dbPort := 6379
	IBMServerPort := 7792
	kvstorePort := 7793
	taggingPort := 7794
	IBMResourceIDPrefix := testResourceIDUSSouth1
	image, zone, instanceName := testImageUSSouth, testZoneUSSouth1, testInstanceNameUSSouth1

	// removes all of paraglide's deployments on IBM
	region, err := ZoneToRegion(zone)
	require.NoError(t, err)

	// Terminate any existing stray deployments if any
	err = TerminateParagliderDeployments(region)
	require.NoError(t, err)

	defer func() {
		time.Sleep(10 * time.Second)
		err := TerminateParagliderDeployments(region)
		require.NoError(t, err)
	}()

	orchestratorServerConfig := config.Config{
		Server: config.Server{
			Host:    "localhost",
			Port:    "9080",
			RpcPort: "9081",
		},
		TagService: config.TagService{
			Host: "localhost",
			Port: strconv.Itoa(taggingPort),
		},
		KVStore: config.TagService{
			Port: strconv.Itoa(kvstorePort),
			Host: "localhost",
		},
		CloudPlugins: []config.CloudPlugin{
			{
				Name: utils.IBM,
				Host: "localhost",
				Port: strconv.Itoa(IBMServerPort),
			},
		},
		Namespaces: map[string][]config.CloudDeployment{
			testNamespace: {
				{
					Name:       utils.IBM,
					Deployment: testDeployment,
				},
			},
		},
	}

	// start controller server
	fmt.Println("Setting up controller server and kvstore server")
	orchestratorServerAddr := orchestratorServerConfig.Server.Host + ":" + orchestratorServerConfig.Server.RpcPort
	orchestrator.Setup(orchestratorServerConfig, true)

	// start ibm plugin server
	fmt.Println("Setting up IBM server")
	ibmServer := Setup(IBMServerPort, orchestratorServerAddr)

	fmt.Println("Setting up kv store server")
	tagging.Setup(dbPort, taggingPort, true)

	fmt.Println("Setting up kv tagging server")
	kvstore.Setup(dbPort, kvstorePort, true)

	// Create IBM VM
	fmt.Println("\nCreating IBM VM...")
	imageIdentity := vpcv1.ImageIdentityByID{ID: &image}
	zoneIdentity := vpcv1.ZoneIdentityByName{Name: &zone}
	myTestProfile := string(testProfile)

	testPrototype := &vpcv1.InstancePrototypeInstanceByImage{
		Image:   &imageIdentity,
		Zone:    &zoneIdentity,
		Name:    core.StringPtr(instanceName),
		Profile: &vpcv1.InstanceProfileIdentityByName{Name: &myTestProfile},
	}

	description, err := json.Marshal(vpcv1.CreateInstanceOptions{InstancePrototype: vpcv1.InstancePrototypeIntf(testPrototype)})
	require.NoError(t, err)

	resource := &paragliderpb.CreateResourceRequest{Name: instanceName, Deployment: &paragliderpb.ParagliderDeployment{Id: testDeployment, Namespace: testNamespace}, Description: description}
	res, err := ibmServer.CreateResource(context.Background(), resource)
	require.NoError(t, err)
	require.NotNil(t, res)
	// append instance's ID
	URIParts := strings.Split(res.Uri, "/")
	resID := IBMResourceIDPrefix + URIParts[len(URIParts)-1]

	// fetch address space from VM ip address
	ipOctets := strings.Split(res.Ip, ".")
	ipOctets[3] = "0"
	resourceAddressSpace := strings.Join(ipOctets, ".") + "/16"

	// Add permit list for IBM VM
	fmt.Println("Adding IBM permit list rules...")

	addRulesRequest := &paragliderpb.AddPermitListRulesRequest{
		Namespace: testNamespace,
		Resource:  resID,
		Rules:     pingTestPermitList,
	}

	resp, err := ibmServer.AddPermitListRules(context.Background(), addRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)

	utils.Log.Printf("Test response: %+v", resp)

	createVPNRequest := &paragliderpb.CreateVpnGatewayRequest{
		Deployment:   &paragliderpb.ParagliderDeployment{Id: testDeployment, Namespace: testNamespace},
		Cloud:        utils.AZURE,
		AddressSpace: resourceAddressSpace,
	}
	fmt.Println("\nCreating IBM VPN...")
	vpnGatewayResp, err := ibmServer.CreateVpnGateway(context.Background(), createVPNRequest)
	require.NoError(t, err)
	require.NotNil(t, vpnGatewayResp)

	utils.Log.Printf("VPN gateway creation response: %v", vpnGatewayResp)

	// random addresses of peer resource on remote cloud.
	// To test connectivity with existing deployment on remote cloud replace below values.
	peerVPNGatewayIP := "4.227.185.167" // remote VPN gateway IP a VPN connection will direct traffic to
	remoteAddressSpace := "10.0.0.0/24" // address space of remote VPC/VNet

	createVPNConnectionRequest := &paragliderpb.CreateVpnConnectionsRequest{
		Deployment:         &paragliderpb.ParagliderDeployment{Id: testDeployment, Namespace: testNamespace},
		GatewayIpAddresses: []string{peerVPNGatewayIP},
		SharedKey:          "password",
		RemoteAddresses:    []string{remoteAddressSpace}, // random address.
		Cloud:              utils.AZURE,
		IsBgpDisabled:      true,
		AddressSpace:       resourceAddressSpace,
	}

	fmt.Println("\nCreating an IBM Connection...")
	vpnConnectionResp, err := ibmServer.CreateVpnConnections(context.Background(), createVPNConnectionRequest)
	require.NoError(t, err)

	utils.Log.Printf("VPN connection creation response: %v", vpnConnectionResp)
}
