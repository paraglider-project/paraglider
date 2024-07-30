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
	"fmt"

	compute "cloud.google.com/go/compute/apiv1"
	container "cloud.google.com/go/container/apiv1"
)

type GCPClients struct {
	instancesClient           *compute.InstancesClient
	clustersClient            *container.ClusterManagerClient
	firewallsClient           *compute.FirewallsClient
	networksClient            *compute.NetworksClient
	subnetworksClient         *compute.SubnetworksClient
	routersClient             *compute.RoutersClient
	vpnGatewaysClient         *compute.VpnGatewaysClient
	vpnTunnelsClient          *compute.VpnTunnelsClient
	externalVpnGatewaysClient *compute.ExternalVpnGatewaysClient
	addressesClient           *compute.AddressesClient
	forwardingClient          *compute.ForwardingRulesClient
	serviceAttachmentClient   *compute.ServiceAttachmentsClient
}

func (c *GCPClients) GetOrCreateInstancesClient(ctx context.Context) (*compute.InstancesClient, error) {
	if c.instancesClient == nil {
		instancesClient, err := compute.NewInstancesRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create InstancesClient: %w", err)
		}
		c.instancesClient = instancesClient
	}
	return c.instancesClient, nil
}

func (c *GCPClients) GetOrCreateClustersClient(ctx context.Context) (*container.ClusterManagerClient, error) {
	if c.clustersClient == nil {
		clustersClient, err := container.NewClusterManagerClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create ClusterManagerClient: %w", err)
		}
		c.clustersClient = clustersClient
	}
	return c.clustersClient, nil
}

func (c *GCPClients) GetOrCreateFirewallsClient(ctx context.Context) (*compute.FirewallsClient, error) {
	if c.firewallsClient == nil {
		firewallsClient, err := compute.NewFirewallsRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create FirewallsClient: %w", err)
		}
		c.firewallsClient = firewallsClient
	}
	return c.firewallsClient, nil
}

func (c *GCPClients) GetOrCreateNetworksClient(ctx context.Context) (*compute.NetworksClient, error) {
	if c.networksClient == nil {
		networksClient, err := compute.NewNetworksRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create NetworksClient: %w", err)
		}
		c.networksClient = networksClient
	}
	return c.networksClient, nil
}

func (c *GCPClients) GetOrCreateSubnetworksClient(ctx context.Context) (*compute.SubnetworksClient, error) {
	if c.subnetworksClient == nil {
		subnetworksClient, err := compute.NewSubnetworksRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create SubnetworksClient: %w", err)
		}
		c.subnetworksClient = subnetworksClient
	}
	return c.subnetworksClient, nil
}

func (c *GCPClients) GetOrCreateRoutersClient(ctx context.Context) (*compute.RoutersClient, error) {
	if c.routersClient == nil {
		routersClient, err := compute.NewRoutersRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create RoutersClient: %w", err)
		}
		c.routersClient = routersClient
	}
	return c.routersClient, nil
}

func (c *GCPClients) GetOrCreateVpnGatewaysClient(ctx context.Context) (*compute.VpnGatewaysClient, error) {
	if c.vpnGatewaysClient == nil {
		vpnGatewaysClient, err := compute.NewVpnGatewaysRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create VpnGatewaysClient: %w", err)
		}
		c.vpnGatewaysClient = vpnGatewaysClient
	}
	return c.vpnGatewaysClient, nil
}

func (c *GCPClients) GetOrCreateVpnTunnelsClient(ctx context.Context) (*compute.VpnTunnelsClient, error) {
	if c.vpnTunnelsClient == nil {
		vpnTunnelsClient, err := compute.NewVpnTunnelsRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create VpnTunnelsClient: %w", err)
		}
		c.vpnTunnelsClient = vpnTunnelsClient
	}
	return c.vpnTunnelsClient, nil
}

func (c *GCPClients) GetOrCreateExternalVpnGatewaysClient(ctx context.Context) (*compute.ExternalVpnGatewaysClient, error) {
	if c.externalVpnGatewaysClient == nil {
		externalVpnGatewaysClient, err := compute.NewExternalVpnGatewaysRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create ExternalVpnGatewaysClient: %w", err)
		}
		c.externalVpnGatewaysClient = externalVpnGatewaysClient
	}
	return c.externalVpnGatewaysClient, nil
}

func (c *GCPClients) GetOrCreateAddressesClient(ctx context.Context) (*compute.AddressesClient, error) {
	if c.addressesClient == nil {
		addressesClient, err := compute.NewAddressesRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create AddressesClient: %w", err)
		}
		c.addressesClient = addressesClient
	}
	return c.addressesClient, nil
}

func (c *GCPClients) GetOrCreateForwardingClient(ctx context.Context) (*compute.ForwardingRulesClient, error) {
	if c.forwardingClient == nil {
		forwardingClient, err := compute.NewForwardingRulesRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create ForwardingRulesClient: %w", err)
		}
		c.forwardingClient = forwardingClient
	}
	return c.forwardingClient, nil
}

func (c *GCPClients) GetOrCreateServiceAttachmentsClient(ctx context.Context) (*compute.ServiceAttachmentsClient, error) {
	if c.serviceAttachmentClient == nil {
		serviceAttachmentClient, err := compute.NewServiceAttachmentsRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create ServiceAttachmentsClient: %w", err)
		}
		c.serviceAttachmentClient = serviceAttachmentClient
	}
	return c.serviceAttachmentClient, nil
}

func (c *GCPClients) Close() {
	if c.instancesClient != nil {
		c.instancesClient.Close()
	}
	if c.clustersClient != nil {
		c.clustersClient.Close()
	}
	if c.firewallsClient != nil {
		c.firewallsClient.Close()
	}
	if c.networksClient != nil {
		c.networksClient.Close()
	}
	if c.subnetworksClient != nil {
		c.subnetworksClient.Close()
	}
	if c.routersClient != nil {
		c.routersClient.Close()
	}
	if c.vpnGatewaysClient != nil {
		c.vpnGatewaysClient.Close()
	}
	if c.vpnTunnelsClient != nil {
		c.vpnTunnelsClient.Close()
	}
	if c.externalVpnGatewaysClient != nil {
		c.externalVpnGatewaysClient.Close()
	}
	if c.addressesClient != nil {
		c.addressesClient.Close()
	}
	if c.forwardingClient != nil {
		c.forwardingClient.Close()
	}
	if c.serviceAttachmentClient != nil {
		c.serviceAttachmentClient.Close()
	}
}
