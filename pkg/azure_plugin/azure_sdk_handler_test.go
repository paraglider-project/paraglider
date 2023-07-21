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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type Response struct {
	Name     string `json:"name"`
	Location string `json:"location"`
}

const testLocation = "eastus"
const subID = "subid-test"
const rgName = "rg-test"
const vmResourceID = "vm-resource-id"

type dummyToken struct {
	azcore.TokenCredential
}

func (d *dummyToken) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}

var azureSDKHandlerTest *azureSDKHandler
var fakeHttpHandler http.HandlerFunc

// a function for setup before all tests
func setup(reqRespMap map[string]Response) {
	if entry, ok := cloud.AzurePublic.Services[cloud.ResourceManager]; ok {
		// Then we modify the copy
		entry.Endpoint = "http://localhost:8080"

		// Then we reassign map entry
		cloud.AzurePublic.Services[cloud.ResourceManager] = entry
	}

	fakeHttpHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Request URL:", r.URL.String())

		// Removing query parameters from the URL to use as the map key
		key := strings.Split(r.URL.String(), "?")[0]
		response := reqRespMap[key]

		fmt.Println("url", key)

		// Check if response is nil or empty
		if len(response.Name) == 0 {
			// Return error response with 404 Not Found status code
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "404 Not Found: The requested resource is not available.")
			return
		}

		// Response found in the map, encode and send the response
		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "500 Internal Server Error: Error encoding response.")
			return
		}
	})

	go func() {
		fmt.Println("Starting server on :8080")
		log.Fatal(http.ListenAndServe(":8080", fakeHttpHandler))
	}()

	azureSDKHandlerTest = &azureSDKHandler{}
	azureSDKHandlerTest.resourceGroupName = rgName
	azureSDKHandlerTest.subscriptionID = subID
	azureSDKHandlerTest.InitializeClients(&dummyToken{})
}

func initializeReqRespMap() map[string]Response {
	// Define the base URL
	nsgURL := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkSecurityGroups", subID, rgName)

	// Define a map of URLs to responses
	urlToResponse := map[string]Response{
		fmt.Sprintf("%s/nsg-success-test", nsgURL): Response{
			Name:     "nsg-success-test",
			Location: testLocation,
		},
		//This one is used by the GetByID req
		fmt.Sprintf("/%s", vmResourceID): Response{
			Name:     "vm-name",
			Location: testLocation,
		},
	}

	return urlToResponse
}

func TestGetSecurityGroup(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	urlToResponse := initializeReqRespMap()
	setup(urlToResponse)

	// Subtest 1: Get security group - Success Test
	t.Run("SuccessTest", func(t *testing.T) {
		expectedNsgNameSuccess := "nsg-success-test"
		nsgSuccess, err := azureSDKHandlerTest.GetSecurityGroup(context.Background(), expectedNsgNameSuccess)

		if err != nil {
			t.Errorf("GetSecurityGroup() error = %v", err)
			return
		}

		if *nsgSuccess.Name != expectedNsgNameSuccess {
			t.Errorf("GetSecurityGroup() got = %v, want %v", *nsgSuccess.Name, expectedNsgNameSuccess)
		}
	})

	// Subtest 2: Get security group - Failure Test
	t.Run("FailureTest", func(t *testing.T) {
		expectedNsgNameFail := "nsg-fail-test"
		nsgFail, err := azureSDKHandlerTest.GetSecurityGroup(context.Background(), expectedNsgNameFail)

		// Check if error is not nil and nsgFail is nil
		if err == nil || nsgFail != nil {
			t.Errorf("GetSecurityGroup() expected an error and nil NSG, but got err = %v, nsg = %v", err, nsgFail)
		}
	})
}

func TestCreateNetworkSecurityGroup(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	urlToResponse := initializeReqRespMap()
	setup(urlToResponse)

	// Create a new context for the tests
	ctx := context.Background()

	// Subtest 1: Create Network Security Group - Success Test
	t.Run("SuccessTest", func(t *testing.T) {
		expectedNsgName := "nsg-success-test"
		expectedLocation := "eastus"

		// Call the function to create the network security group
		nsg, err := azureSDKHandlerTest.CreateNetworkSecurityGroup(ctx, expectedNsgName, expectedLocation)

		if err != nil {
			t.Errorf("CreateNetworkSecurityGroup() error = %v", err)
			return
		}

		// Check if the created NSG has the expected name and location
		if nsg == nil {
			t.Errorf("CreateNetworkSecurityGroup() returned nil SecurityGroup")
			return
		}

		if *nsg.Name != expectedNsgName {
			t.Errorf("CreateNetworkSecurityGroup() got = %v, want %v", *nsg.Name, expectedNsgName)
		}

		if *nsg.Location != expectedLocation {
			t.Errorf("CreateNetworkSecurityGroup() got = %v, want %v", *nsg.Location, expectedLocation)
		}
	})

	// Subtest 2: Create Network Security Group - Failure Test
	t.Run("FailureTest", func(t *testing.T) {
		// We can create a failure test case by trying to create an NSG with an existing name and location
		existingNsgName := "existing-nsg"
		existingLocation := "westus"

		// Call the function to create the network security group
		nsg, err := azureSDKHandlerTest.CreateNetworkSecurityGroup(ctx, existingNsgName, existingLocation)

		// Check if the function returns an error as expected
		if err == nil {
			t.Errorf("CreateNetworkSecurityGroup() expected an error, but got nil")
			return
		}

		// Check if the created NSG is nil (should not be created due to the error)
		if nsg != nil {
			t.Errorf("CreateNetworkSecurityGroup() expected a nil SecurityGroup, but got %v", nsg)
		}
	})
}

// func TestGetResourceNIC(t *testing.T) {
// 	// Initialize and set up the test scenario with the appropriate responses
// 	urlToResponse := initializeReqRespMap()
// 	setup(urlToResponse)

// 	// Create a new context for the tests
// 	ctx := context.Background()

// 	// Test 1: Successful GetResourceNIC for a VM
// 	t.Run("VMTest", func(t *testing.T) {
// 		// Set up your mock responses and expectations for the test
// 		vmResourceID := "vm-resource-id"
// 		// nicResourceID := "nic-resource-id"

// 		// Call the function to test
// 		nic, err := azureSDKHandlerTest.GetResourceNIC(ctx, vmResourceID)

// 		// Write assertions to verify the result and behavior

// 		// Example assertion:
// 		if err != nil {
// 			t.Errorf("GetResourceNIC() returned an unexpected error: %v", err)
// 			return
// 		}
// 		// Check if the created NSG has the expected name and location
// 		if nic == nil {
// 			t.Errorf("CreateNetworkSecurityGroup() returned nil SecurityGroup")
// 			return
// 		}

// 		if *nic.Name !=  {
// 			t.Errorf("CreateNetworkSecurityGroup() got = %v, want %v", *nsg.Name, expectedNsgName)
// 		}

// 		if *nsg.Location != expectedLocation {
// 			t.Errorf("CreateNetworkSecurityGroup() got = %v, want %v", *nsg.Location, expectedLocation)
// 		}.
// 	})
// }
