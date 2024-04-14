import requests
from uuid import uuid4
REGION = "us-east"
ZONE = "us-east-1"
NAME = "instanceName"+str(uuid4())[:6]
PROFILE = "bx2-2x8"
FRONTEND_SERVER_ADDR = "127.0.0.1:8080"
CLOUD_NAME = "ibm"
IGNORED_STR_FIELD = "ignored"
IGNORED_INT_FIELD = 1


vm_data = {
    "id": f"/ResourceGroupName/{IGNORED_STR_FIELD}/Region/{IGNORED_STR_FIELD}/ResourceID/{IGNORED_STR_FIELD}",
    "description": f"""
    {{
        "profile": "{PROFILE}",
        "zone": "{ZONE}",
        "name": "{NAME}"
    }}"""
}


r = requests.post(f"http://{FRONTEND_SERVER_ADDR}/cloud/{CLOUD_NAME}/resources/{IGNORED_INT_FIELD}/",
                  headers={"Content-Type": "application/json"}, json=vm_data)
print(r.text)


# // usage: go test --tags=ibm -run TestMulticloudIBMAzure -sg=<security group name> -timeout 0
# // -timeout 0 removes limit of 10 min. runtime, which is necessary due to long deployment time of Azure's VPN.
# func TestMulticloudIBMAzure(t *testing.T) {
# 	// ibm config
# 	IBMServerPort := 7992
# 	IBMDeploymentID := testResourceIDUSEast1
# 	image, zone, instanceName, resourceID := testImageUSEast, testZoneUSEast1, testInstanceNameUSEast1, testResourceIDUSEast1
# 	// azure config
# 	azureServerPort := 7991
# 	azureResourceGroupName := "challenge-1377"
# 	azureSubscriptionId := azure_plugin.GetAzureSubscriptionId()
# 	// TODO REPLACE BELOW STATIC NAME WITH uuid.newString()
# 	azureNamespace := "multicloud708"
# 	AzureDeploymentID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/...", azureSubscriptionId, azureResourceGroupName)

# 	// defer azure_plugin.TeardownAzureTesting(azureSubscriptionId, azureResourceGroupName)

# 	orchestratorServerConfig := config.Config{
# 		CloudPlugins: []config.CloudPlugin{
# 			{
# 				Name: utils.IBM,
# 				Host: "localhost",
# 				Port: strconv.Itoa(IBMServerPort),
# 			},

# 			{
# 				Name: utils.AZURE,
# 				Host: "localhost",
# 				Port: strconv.Itoa(azureServerPort),
# 			},
# 		},
# 		Namespaces: map[string][]config.CloudDeployment{
# 			testNamespace: {
# 				{
# 					Name:       utils.IBM,
# 					Deployment: IBMDeploymentID,
# 				},
# 			},
# 			azureNamespace: {
# 				{
# 					Name:       utils.AZURE,
# 					Deployment: AzureDeploymentID,
# 				},
# 			},
# 		},
# 	}

# 	// start controller server
# 	orchestratorServerAddr := orchestrator.SetupControllerServer(orchestratorServerConfig)
# 	fmt.Println("Setup controller server")

# 	// start ibm plugin server
# 	fmt.Println("Setting up IBM server")
# 	ibmServer := Setup(IBMServerPort, orchestratorServerAddr)

# 	// start azure plugin server
# 	fmt.Println("Setting up Azure server")
# 	azureServer := azure_plugin.Setup(azureServerPort, orchestratorServerAddr)

# 	ctx := context.Background()

# 	// Create Azure VM
# 	fmt.Println("Creating Azure VM...")
# 	azureVm1Location := "westus"
# 	azureVm1Parameters := azure_plugin.GetTestVmParameters(azureVm1Location)
# 	azureVm1Description, err := json.Marshal(azureVm1Parameters)
# 	azureVm1ResourceId := "/subscriptions/" + azureSubscriptionId + "/resourceGroups/" + azureResourceGroupName + "/providers/Microsoft.Compute/virtualMachines/" + "invisinets-vm-multicloud708"
# 	azureCreateResourceResp1, err := azureServer.CreateResource(
# 		ctx,
# 		&invisinetspb.ResourceDescription{Id: azureVm1ResourceId, Description: azureVm1Description, Namespace: azureNamespace},
# 	)
# 	require.NoError(t, err)
# 	require.NoError(t, err)
# 	require.NotNil(t, azureCreateResourceResp1)
# 	assert.Equal(t, azureCreateResourceResp1.Uri, azureVm1ResourceId)

# 	// // Create IBM VM
# 	fmt.Println("Creating IBM VM...")
# 	imageIdentity := vpcv1.ImageIdentityByID{ID: &image}
# 	zoneIdentity := vpcv1.ZoneIdentityByName{Name: &zone}
# 	myTestProfile := string(testProfile)

# 	testPrototype := &vpcv1.InstancePrototypeInstanceByImage{
# 		Image:   &imageIdentity,
# 		Zone:    &zoneIdentity,
# 		Name:    core.StringPtr(instanceName),
# 		Profile: &vpcv1.InstanceProfileIdentityByName{Name: &myTestProfile},
# 	}

# 	description, err := json.Marshal(vpcv1.CreateInstanceOptions{InstancePrototype: vpcv1.InstancePrototypeIntf(testPrototype)})
# 	require.NoError(t, err)

# 	resource := &invisinetspb.ResourceDescription{Id: resourceID, Description: description, Namespace: testNamespace}
# 	createResourceResponse, err := ibmServer.CreateResource(ctx, resource)
# 	if err != nil {
# 		println(err)
# 	}
# 	require.NoError(t, err)
# 	require.NotNil(t, createResourceResponse)

# 	// Add permit list for IBM VM 1
# 	fmt.Println("Adding IBM permit list rules...")
# 	azureVm1IpAddress, err := azure_plugin.GetVmIpAddress(azureVm1ResourceId)
# 	require.NoError(t, err)

# 	ibmPermitList := []*invisinetspb.PermitListRule{
# 		//inbound ICMP protocol rule to accept & respond to pings
# 		{
# 			Direction: invisinetspb.Direction_INBOUND,
# 			SrcPort:   -1,
# 			DstPort:   -1,
# 			Protocol:  1,
# 			Targets:   []string{azureVm1IpAddress},
# 		},
# 		//outbound ICMP protocol rule to initiate pings
# 		{
# 			Direction: invisinetspb.Direction_OUTBOUND,
# 			SrcPort:   -1,
# 			DstPort:   -1,
# 			Protocol:  1,
# 			Targets:   []string{azureVm1IpAddress},
# 		},
# 		// allow inbound ssh connection
# 		{
# 			Direction: invisinetspb.Direction_INBOUND,
# 			SrcPort:   22,
# 			DstPort:   22,
# 			Protocol:  6,
# 			Targets:   []string{"0.0.0.0/0"},
# 		},
# 	}

# 	addRulesRequest := &invisinetspb.AddPermitListRulesRequest{
# 		Namespace: testNamespace,
# 		Resource:  IBMDeploymentID,
# 		Rules:     ibmPermitList,
# 	}

# 	respAddRules, err := ibmServer.AddPermitListRules(ctx, addRulesRequest)
# 	require.NoError(t, err)
# 	require.NotNil(t, respAddRules)

# 	// Create Azure VM1 permit list
# 	ibmVmIpAddress := createResourceResponse.Ip

# 	fmt.Println("Adding Azure permit list rules...")
# 	azureVm1PermitListReq := &invisinetspb.AddPermitListRulesRequest{
# 		Resource: azureVm1ResourceId,
# 		Rules: []*invisinetspb.PermitListRule{
# 			{
# 				Name:      "ibm-inbound-rule",
# 				Direction: invisinetspb.Direction_INBOUND,
# 				SrcPort:   -1,
# 				DstPort:   -1,
# 				Protocol:  1,
# 				Targets:   []string{ibmVmIpAddress},
# 			},
# 			{
# 				Name:      "ibm-outbound-rule",
# 				Direction: invisinetspb.Direction_OUTBOUND,
# 				SrcPort:   -1,
# 				DstPort:   -1,
# 				Protocol:  1,
# 				Targets:   []string{ibmVmIpAddress},
# 			},
# 			{ // SSH rule for debugging
# 				Name:      "ssh-inbound-rule",
# 				Direction: invisinetspb.Direction_INBOUND,
# 				SrcPort:   -1,
# 				DstPort:   22,
# 				Protocol:  6,
# 				Targets:   []string{"0.0.0.0/0"},
# 			},
# 		},
# 		Namespace: azureNamespace,
# 	}
# 	azureAddPermitListRules1Resp, err := azureServer.AddPermitListRules(ctx, azureVm1PermitListReq)
# 	require.NoError(t, err)
# 	require.NotNil(t, azureAddPermitListRules1Resp)

# 	// Run Azure connectivity check (ping from Azure VM to IBM VM)
# 	fmt.Println("running Azure connectivity test...")
# 	azureConnectivityCheck1, err := azure_plugin.RunPingConnectivityCheck(azureVm1ResourceId, ibmVmIpAddress)
# 	require.Nil(t, err)
# 	require.True(t, azureConnectivityCheck1)
# }
