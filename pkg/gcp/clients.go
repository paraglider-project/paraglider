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
	InstancesClient           *compute.InstancesClient
	ClustersClient            *container.ClusterManagerClient
	FirewallsClient           *compute.FirewallsClient
	NetworksClient            *compute.NetworksClient
	SubnetworksClient         *compute.SubnetworksClient
	RoutersClient             *compute.RoutersClient
	VpnGatewaysClient         *compute.VpnGatewaysClient
	VpnTunnelsClient          *compute.VpnTunnelsClient
	ExternalVpnGatewaysClient *compute.ExternalVpnGatewaysClient
	AddressesClient           *compute.AddressesClient
	ForwardingClient          *compute.ForwardingRulesClient
	ServiceAttachmentClient   *compute.ServiceAttachmentsClient
}

func (c *GCPClients) GetInstancesClient(ctx context.Context) (*compute.InstancesClient, error) {
	if c.InstancesClient == nil {
		instancesClient, err := compute.NewInstancesRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create InstancesClient: %w", err)
		}
		c.InstancesClient = instancesClient
	}
	return c.InstancesClient, nil
}

func (c *GCPClients) GetClustersClient(ctx context.Context) (*container.ClusterManagerClient, error) {
	if c.ClustersClient == nil {
		clustersClient, err := container.NewClusterManagerClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create ClusterManagerClient: %w", err)
		}
		c.ClustersClient = clustersClient
	}
	return c.ClustersClient, nil
}

func (c *GCPClients) GetFirewallsClient(ctx context.Context) (*compute.FirewallsClient, error) {
	if c.FirewallsClient == nil {
		firewallsClient, err := compute.NewFirewallsRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create FirewallsClient: %w", err)
		}
		c.FirewallsClient = firewallsClient
	}
	return c.FirewallsClient, nil
}

func (c *GCPClients) GetNetworksClient(ctx context.Context) (*compute.NetworksClient, error) {
	if c.NetworksClient == nil {
		networksClient, err := compute.NewNetworksRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create NetworksClient: %w", err)
		}
		c.NetworksClient = networksClient
	}
	return c.NetworksClient, nil
}

func (c *GCPClients) GetSubnetworksClient(ctx context.Context) (*compute.SubnetworksClient, error) {
	if c.SubnetworksClient == nil {
		subnetworksClient, err := compute.NewSubnetworksRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create SubnetworksClient: %w", err)
		}
		c.SubnetworksClient = subnetworksClient
	}
	return c.SubnetworksClient, nil
}

func (c *GCPClients) GetRoutersClient(ctx context.Context) (*compute.RoutersClient, error) {
	if c.RoutersClient == nil {
		routersClient, err := compute.NewRoutersRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create RoutersClient: %w", err)
		}
		c.RoutersClient = routersClient
	}
	return c.RoutersClient, nil
}

func (c *GCPClients) GetVpnGatewaysClient(ctx context.Context) (*compute.VpnGatewaysClient, error) {
	if c.VpnGatewaysClient == nil {
		vpnGatewaysClient, err := compute.NewVpnGatewaysRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create VpnGatewaysClient: %w", err)
		}
		c.VpnGatewaysClient = vpnGatewaysClient
	}
	return c.VpnGatewaysClient, nil
}

func (c *GCPClients) GetVpnTunnelsClient(ctx context.Context) (*compute.VpnTunnelsClient, error) {
	if c.VpnTunnelsClient == nil {
		vpnTunnelsClient, err := compute.NewVpnTunnelsRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create VpnTunnelsClient: %w", err)
		}
		c.VpnTunnelsClient = vpnTunnelsClient
	}
	return c.VpnTunnelsClient, nil
}

func (c *GCPClients) GetExternalVpnGatewaysClient(ctx context.Context) (*compute.ExternalVpnGatewaysClient, error) {
	if c.ExternalVpnGatewaysClient == nil {
		externalVpnGatewaysClient, err := compute.NewExternalVpnGatewaysRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create ExternalVpnGatewaysClient: %w", err)
		}
		c.ExternalVpnGatewaysClient = externalVpnGatewaysClient
	}
	return c.ExternalVpnGatewaysClient, nil
}

func (c *GCPClients) GetAddressesClient(ctx context.Context) (*compute.AddressesClient, error) {
	if c.AddressesClient == nil {
		addressesClient, err := compute.NewAddressesRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create AddressesClient: %w", err)
		}
		c.AddressesClient = addressesClient
	}
	return c.AddressesClient, nil
}

func (c *GCPClients) GetForwardingClient(ctx context.Context) (*compute.ForwardingRulesClient, error) {
	if c.ForwardingClient == nil {
		forwardingClient, err := compute.NewForwardingRulesRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create ForwardingRulesClient: %w", err)
		}
		c.ForwardingClient = forwardingClient
	}
	return c.ForwardingClient, nil
}

func (c *GCPClients) GetServiceAttachmentsClient(ctx context.Context) (*compute.ServiceAttachmentsClient, error) {
	if c.ServiceAttachmentClient == nil {
		serviceAttachmentClient, err := compute.NewServiceAttachmentsRESTClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("Failed to create ServiceAttachmentsClient: %w", err)
		}
		c.ServiceAttachmentClient = serviceAttachmentClient
	}
	return c.ServiceAttachmentClient, nil
}

func (c *GCPClients) Close() {
	if c.InstancesClient != nil {
		c.InstancesClient.Close()
	}
	if c.ClustersClient != nil {
		c.ClustersClient.Close()
	}
	if c.FirewallsClient != nil {
		c.FirewallsClient.Close()
	}
	if c.NetworksClient != nil {
		c.NetworksClient.Close()
	}
	if c.SubnetworksClient != nil {
		c.SubnetworksClient.Close()
	}
	if c.RoutersClient != nil {
		c.RoutersClient.Close()
	}
	if c.VpnGatewaysClient != nil {
		c.VpnGatewaysClient.Close()
	}
	if c.VpnTunnelsClient != nil {
		c.VpnTunnelsClient.Close()
	}
	if c.ExternalVpnGatewaysClient != nil {
		c.ExternalVpnGatewaysClient.Close()
	}
	if c.AddressesClient != nil {
		c.AddressesClient.Close()
	}
	if c.ForwardingClient != nil {
		c.ForwardingClient.Close()
	}
	if c.ServiceAttachmentClient != nil {
		c.ServiceAttachmentClient.Close()
	}
}
