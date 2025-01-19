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

package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

func resourceExistsCheck(ctx context.Context, handler *AzureSDKHandler, resourceId string) (*paragliderpb.CheckResult, error) {
	res := &paragliderpb.CheckResult{Status: paragliderpb.CheckStatus_OK}
	_, err := ValidateResourceExists(ctx, handler, resourceId)
	if err == nil {
		res.Status = paragliderpb.CheckStatus_OK
	} else {
		// todo: Do this check in a different way. This format is based on return text in err msg
		errorText := textBetween(err.Error(), "ERROR CODE", "\n")
		if strings.Contains(errorText, "NotFound") {
			res.Status = paragliderpb.CheckStatus_FAIL
			err = nil // reset error to signify the reason for the failure has been identified as resource Not found
		}
	}

	return res, err
}

func networkCheck(ctx context.Context, handler *AzureSDKHandler, resourceId string) (*paragliderpb.CheckResult, *resourceNetworkInfo, *armnetwork.VirtualNetwork, error) {
	res := &paragliderpb.CheckResult{}
	networkInfo, err := GetNetworkInfoFromResource(ctx, handler, resourceId)
	if err != nil {
		errorText := textBetween(err.Error(), "ERROR CODE", "\n")
		if strings.Contains(errorText, "NotFound") {
			if strings.HasPrefix(err.Error(), "NIC") {
				res.Status = paragliderpb.CheckStatus_FAIL
				res.Messages = []string{"Error with Network Interface:\n", err.Error()}
				return res, networkInfo, nil, nil
			} else {
				return nil, nil, nil, err
			}
		} else {
			return nil, nil, nil, err
		}
	}

	// NSG, NIC, and Subnet Exists
	vnet, err := handler.GetVirtualNetwork(ctx, getVnetFromSubnetId(networkInfo.SubnetID))
	if err != nil {
		res.Status = paragliderpb.CheckStatus_FAIL
		res.Messages = []string{"Error with Virtual Network:\n", err.Error()}
		return res, networkInfo, vnet, nil
	}

	if !isProvisioned(vnet.Properties.ProvisioningState) {
		res.Status = paragliderpb.CheckStatus_FAIL
		res.Messages = []string{"Virtual Network is not provisioned"}
		return res, networkInfo, vnet, nil
	}

	res.Status = paragliderpb.CheckStatus_OK
	return res, networkInfo, vnet, nil
}

func permitListConfigCheck(ctx context.Context, handler *AzureSDKHandler, nsg *armnetwork.SecurityGroup, attemptFix bool) (*paragliderpb.CheckResult, error) {
	res := &paragliderpb.CheckResult{}
	if !isProvisioned(nsg.Properties.ProvisioningState) {
		res.Status = paragliderpb.CheckStatus_FAIL
		res.Messages = []string{"Network Security Group is not provisioned"}
		return res, nil
	}

	isNSGCompliant, _ := CheckSecurityRulesCompliance(ctx, handler, nsg)
	if isNSGCompliant {
		res.Status = paragliderpb.CheckStatus_OK
	} else {
		res.Status = paragliderpb.CheckStatus_FAIL
		res.Messages = []string{"Security rules are not compliant"}
		if attemptFix {
			// todo: Fix the security rules
		}
	}

	return res, nil
}

func publicConnectionsCheck(ctx context.Context, handler *AzureSDKHandler, location string, attemptFix bool) (*paragliderpb.CheckResult, error) {
	res := &paragliderpb.CheckResult{}
	hasNAT := false
	createdNAT := false

	if attemptFix {
		_, err := getOrCreateNatGateway(ctx, handler, namespace, location)
		createdNAT = (err == nil)
	} else {
		natGatewayName := getNatGatewayName(namespace, location)
		_, err := handler.GetNatGateway(ctx, natGatewayName)
		hasNAT = (err == nil)
	}

	if hasNAT {
		res.Status = paragliderpb.CheckStatus_OK
	} else if createdNAT {
		res.Status = paragliderpb.CheckStatus_FIXED
	} else {
		// Resource should have a NAT if it references a public IP
		res.Status = paragliderpb.CheckStatus_FAIL
		res.Messages = []string{"Resource should have a NAT Gateway"}
	}

	return res, nil
}

func intraCloudCheck(
	ctx context.Context,
	s *azurePluginServer,
	handler *AzureSDKHandler,
	resourceIdInfo ResourceIDInfo,
	vnet *armnetwork.VirtualNetwork,
	peerVnets map[string]*utils.PeeringCloudInfo,
	targets map[*utils.PeeringCloudInfo]string,
	attemptFix bool,
) (*paragliderpb.CheckResult, error) {

	res := &paragliderpb.CheckResult{Messages: make([]string, 0)}
	peerings := vnet.Properties.VirtualNetworkPeerings
	var target string
	// Check each peering to the vnet and
	for _, peering := range peerings {
		peeredVnetId := *peering.Properties.RemoteVirtualNetwork.ID
		brokenPeering := false
		peeringCloudInfo, ok := peerVnets[peeredVnetId]
		if ok {
			if *peering.Properties.PeeringState != armnetwork.VirtualNetworkPeeringStateConnected {
				brokenPeering = true
				target = targets[peeringCloudInfo]
			} else {
				// Remove the peer vnet from the map to signify that it is connected
				delete(peerVnets, peeredVnetId)
			}
		}

		if brokenPeering {
			if attemptFix {
				err := s.createPeering(ctx, *handler, resourceIdInfo, *vnet.Name, peeringCloudInfo, target)
				if err == nil {
					delete(peerVnets, peeredVnetId)
				} else {
					res.Messages = append(res.Messages, fmt.Sprintf("Error creating peering to vnet %s", *vnet.ID))
				}
			} else {
				res.Messages = append(res.Messages, "Peering to vnet not connected")
			}
		}
	}

	// All connected peer vnets should be deleted from the peer vnets map
	if len(peerVnets) > 0 {
		res.Status = paragliderpb.CheckStatus_FAIL
	} else if attemptFix {
		res.Status = paragliderpb.CheckStatus_FIXED
	} else {
		res.Status = paragliderpb.CheckStatus_OK
	}

	return res, nil
}

// Check that the targets of the permit lists exists
// Also return whether the resource has any multicloud or public cloud connections
// PeerVnets is a map of peer Vnet IDs to thier peering cloud info
// Targets is a map of peering cloud info to the target IP
func permitListsTargetCheck(
	ctx context.Context,
	s *azurePluginServer,
	handler *AzureSDKHandler,
	networkInfo *resourceNetworkInfo,
	namespace string,
	attemptFix bool,
) (res *paragliderpb.CheckResult, publicCloud bool, multiCloud bool, peerVnets map[string]*utils.PeeringCloudInfo, targets map[*utils.PeeringCloudInfo]string, err error) {

	res = &paragliderpb.CheckResult{}
	publicCloud = false
	multiCloud = false
	// Map of vnet name to peering cloud info
	peerVnets = make(map[string]*utils.PeeringCloudInfo)
	// Map of peering cloud info to target IP
	targets = make(map[*utils.PeeringCloudInfo]string)

	vnetName := getVnetFromSubnetId(networkInfo.SubnetID)
	vnet, err := handler.GetVirtualNetwork(ctx, vnetName)
	if err != nil {
		utils.Log.Printf("An error occured while getting vnet:%+v", err)
		return
	}

	// Get subnets address spaces
	localVnetAddressSpaces := []string{}
	for _, addressSpace := range vnet.Properties.AddressSpace.AddressPrefixes {
		localVnetAddressSpaces = append(localVnetAddressSpaces, *addressSpace)
	}
	if len(localVnetAddressSpaces) == 0 {
		err = fmt.Errorf("unable to get subnet address prefix for vnet")
		return
	}

	// Tracks IPs associated to any deleted rule. Used when attempting fixes.
	deletedIps := map[string]bool{}
	visitedIps := map[string]bool{}

	// Get used address spaces of all clouds
	orchestratorConn, err := grpc.NewClient(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		err = fmt.Errorf("unable to establish connection with orchestrator: %w", err)
		return
	}
	defer orchestratorConn.Close()
	orchestratorClient := paragliderpb.NewControllerClient(orchestratorConn)
	getUsedAddressSpacesResp, err := orchestratorClient.GetUsedAddressSpaces(context.Background(), &emptypb.Empty{})
	if err != nil {
		err = fmt.Errorf("unable to get used address spaces: %w", err)
		return
	}

	// Get permit lists for resource
	rules, err := getPermitListsFromRules(handler, networkInfo.NSG.Properties.SecurityRules, false)
	if err != nil {
		err = fmt.Errorf("unable to get permit lists from rules: %w", err)
		return
	}

	var peeringCloudInfos []*utils.PeeringCloudInfo
	for _, rule := range rules {
		peeringCloudInfos, err = utils.GetPermitListRulePeeringCloudInfo(rule, getUsedAddressSpacesResp.AddressSpaceMappings)
		if err != nil {
			err = fmt.Errorf("unable to get peering cloud infos: %w", err)
			return
		}

		for i, peeringCloudInfo := range peeringCloudInfos {
			// If the rule has no tag for the target, skip
			// May be because the resource was attached and Paraglider does not know about targets
			if i >= len(rule.Tags) {
				continue
			}

			peerTag := rule.Tags[i]
			peerIp := rule.Targets[i]
			// For check, no need to check the same IP twice if both inbound and outbound rules exist
			// For fix, both inbound and outbound rules need to be deleted
			if visitedIps[peerIp] && !attemptFix {
				continue // Skip if the IP has already been visited and checked
			}

			if peeringCloudInfo == nil {
				publicCloud = true // Public IP
			} else {
				// If a deleted IP is seen in another rule, it means the rule is
				// in the opposite direction(in vs outbound) and should also be deleted
				if deletedIps[peerIp] && attemptFix {
					err = handler.DeleteSecurityRule(ctx, *networkInfo.NSG.Name, rule.Name)
					// If any check fails, the status should be set to FAIL
					if err == nil && res.Status != paragliderpb.CheckStatus_FAIL {
						res.Status = paragliderpb.CheckStatus_FIXED
					} else {
						res.Status = paragliderpb.CheckStatus_FAIL
					}
					continue
				}

				// Get the URI for the peered resource
				var uriReq *paragliderpb.RetrieveUriRequest
				var uriResp *paragliderpb.RetrieveUriResponse
				var peerInfo ResourceIDInfo
				var peerHandler *AzureSDKHandler
				if peeringCloudInfo.Cloud == utils.AZURE {
					// Azure will self handle validation of azure resources.
					// Only retrieve the peer URI from orchestrator. Don't validate through the orchestrator
					uriReq = &paragliderpb.RetrieveUriRequest{TagName: peerTag, Cloud: utils.AZURE, ShouldValidate: false}
					uriResp, err = orchestratorClient.RetrieveUriFromTag(ctx, uriReq)
					if err != nil {
						err = fmt.Errorf("unable to get uri from ip: %w", err)
						res.Status = paragliderpb.CheckStatus_FAIL
						return
					}

					peerUri := uriResp.Uri
					peerInfo, err = getResourceIDInfo(peerUri)
					if err != nil {
						utils.Log.Printf("An error occured while getting resource id info:%+v", err)
						res.Status = paragliderpb.CheckStatus_FAIL
						return
					}
					// The namespace doesn't matter for this peer handler setup
					// because this handler is setup to only validate if the resource exists on the cloud
					peerHandler, err = s.setupAzureHandler(peerInfo, namespace)
					if err != nil {
						res.Status = paragliderpb.CheckStatus_FAIL
						return
					}

					// Validation of the peer resource
					_, err = ValidateResourceExists(ctx, peerHandler, peerUri)
					if err == nil {
						uriResp.Validated = true
					}

					var isLocal bool
					var peerVnet *armnetwork.VirtualNetwork
					var peerNetworkInfo *resourceNetworkInfo
					// Non-local vnets need to identified for peering validation
					if uriResp.Validated {
						isLocal, err = utils.IsPermitListRuleTagInAddressSpace(peerIp, localVnetAddressSpaces)
						if err != nil {
							res.Status = paragliderpb.CheckStatus_FAIL
							return
						}
						if !isLocal {
							peerNetworkInfo, err = GetNetworkInfoFromResource(ctx, peerHandler, peerUri)
							if err != nil {
								res.Status = paragliderpb.CheckStatus_FAIL
								return
							}
							peerVnetName := getVnetFromSubnetId(peerNetworkInfo.SubnetID)
							peerVnet, err = peerHandler.GetVirtualNetwork(ctx, peerVnetName)
							if err != nil {
								res.Status = paragliderpb.CheckStatus_FAIL
								return
							}
							// Tracks the vnet id for each peering cloud info
							peerVnets[*peerVnet.ID] = peeringCloudInfo
							// Tracks the target IP for each peering cloud info
							targets[peeringCloudInfo] = peerIp
						}
					}
				} else {
					// External cloud should validate that resource exists (through the orchestrator)
					uriReq = &paragliderpb.RetrieveUriRequest{TagName: peerTag, Cloud: utils.AZURE, ShouldValidate: true}
					uriResp, err = orchestratorClient.RetrieveUriFromTag(ctx, uriReq)
					if err != nil {
						err = fmt.Errorf("unable to get uri from ip: %w", err)
						res.Status = paragliderpb.CheckStatus_FAIL
						return
					}
					// Multi connection exists if cross-cloud resource is validated/exists
					multiCloud = multiCloud || uriResp.Validated
				}

				if !uriResp.Validated {
					// The peered resource doesn't exist
					res.Status = paragliderpb.CheckStatus_FAIL

					// Attempt fixing by deleting the rule
					if attemptFix {
						err = handler.DeleteSecurityRule(ctx, *networkInfo.NSG.Name, rule.Name)
						if err == nil {
							deletedIps[peerIp] = true
							if res.Status != paragliderpb.CheckStatus_FAIL {
								res.Status = paragliderpb.CheckStatus_FIXED
							}
						} else {
							// Add error message if fix failed
							res.Messages = append(res.Messages, fmt.Sprintf("Failed to delete permit list to resource: %s", peerTag))
						}
					} else {
						res.Messages = append(res.Messages, fmt.Sprintf("Peered resource doesn't exist: %s", peerTag))
					}
				}
			}

			visitedIps[peerIp] = true
		}
	}

	return
}
