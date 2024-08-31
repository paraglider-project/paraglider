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

package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/paraglider-project/paraglider/pkg/paragliderpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type AwsPluginServer struct {
	paragliderpb.UnimplementedCloudPluginServer
	orchestratorServerAddr string
}

func (s *AwsPluginServer) CreateResource(ctx context.Context, req *paragliderpb.CreateResourceRequest) (*paragliderpb.CreateResourceResponse, error) {
	return s._CreateResource(ctx, req, &awsClients{})
}

func (s *AwsPluginServer) _CreateResource(ctx context.Context, req *paragliderpb.CreateResourceRequest, awsClients *awsClients) (*paragliderpb.CreateResourceResponse, error) {
	// Unmarshal resource description
	runInstancesInput := &ec2.RunInstancesInput{}
	err := json.Unmarshal(req.Description, runInstancesInput)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal resource description: %w", err)
	}

	// Ensure resource description does not contain networking information
	if len(runInstancesInput.NetworkInterfaces) > 0 {
		return nil, fmt.Errorf("resource description should not contain network interfaces")
	}
	if len(runInstancesInput.SecurityGroupIds) > 0 || len(runInstancesInput.SecurityGroups) > 0 {
		return nil, fmt.Errorf("resource description should not contain security groups")
	}
	if runInstancesInput.SubnetId != nil {
		return nil, fmt.Errorf("resource description should not contain subnet ID")
	}
	if runInstancesInput.PrivateIpAddress != nil || runInstancesInput.EnablePrimaryIpv6 != nil ||
		runInstancesInput.Ipv6AddressCount != nil || len(runInstancesInput.Ipv6Addresses) > 0 {
		return nil, fmt.Errorf("resource description should not contain IP address information")
	}

	// Get region
	availabilityZone := *runInstancesInput.Placement.AvailabilityZone
	region := getRegionFromAvailabilityZone(availabilityZone)

	// Load config and setup clients
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load config: %w", err)
	}
	ec2Client := awsClients.getOrCreateEc2Client(cfg)

	// Get existing VPC
	var vpc *types.Vpc
	var subnet *types.Subnet
	vpcName := getVpcName(req.Deployment.Namespace, region)
	describeVpcsOutput, err := ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		Filters: getDescribeFilter(req.Deployment.Namespace, vpcName),
	})
	if err != nil {
		return nil, fmt.Errorf("unable to get VPCs: %w", err)
	}
	if len(describeVpcsOutput.Vpcs) <= 1 {
		if len(describeVpcsOutput.Vpcs) == 1 {
			vpc = &describeVpcsOutput.Vpcs[0]
		} else {
			// Find unused address spaces from orchestrator
			orchestratorConn, err := grpc.NewClient(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				return nil, fmt.Errorf("unable to establish connection with orchestrator: %w", err)
			}
			defer orchestratorConn.Close()
			orchestratorClient := paragliderpb.NewControllerClient(orchestratorConn)
			findUnusedAddressSpacesReq := &paragliderpb.FindUnusedAddressSpacesRequest{}
			findUnusedAddressSpacesResp, err := orchestratorClient.FindUnusedAddressSpaces(ctx, findUnusedAddressSpacesReq)
			if err != nil {
				return nil, fmt.Errorf("unable to find unused address spaces from orchestrator: %w", err)
			}
			vpcCidrBlock := findUnusedAddressSpacesResp.AddressSpaces[0]

			// Create VPC
			createVpcInput := &ec2.CreateVpcInput{
				CidrBlock:         aws.String(vpcCidrBlock),
				TagSpecifications: getTagSpecificationsForCreateResource(req.Deployment.Namespace, vpcName, types.ResourceTypeVpc),
			}
			createVpcOutput, err := ec2Client.CreateVpc(ctx, createVpcInput)
			if err != nil {
				return nil, fmt.Errorf("unable to create VPC: %w", err)
			}
			vpc = createVpcOutput.Vpc

			// Wait until default security group is available
			securityGroupExistsWaiter := ec2.NewSecurityGroupExistsWaiter(ec2Client)
			err = securityGroupExistsWaiter.Wait(ctx, &ec2.DescribeSecurityGroupsInput{
				Filters: []types.Filter{
					{Name: aws.String("vpc-id"), Values: []string{*createVpcOutput.Vpc.VpcId}},
				},
			}, 10*time.Second)
			if err != nil {
				return nil, fmt.Errorf("unable to wait for default security group: %w", err)
			}

			// Remove default inbound and outbound rules from default security group
			getSecurityGroupInput := &ec2.DescribeSecurityGroupsInput{
				Filters: []types.Filter{
					{Name: aws.String("vpc-id"), Values: []string{*vpc.VpcId}},
				},
			}
			describeSecurityGroupsOutput, err := ec2Client.DescribeSecurityGroups(ctx, getSecurityGroupInput)
			if err != nil {
				return nil, fmt.Errorf("unable to get security groups: %w", err)
			}
			if len(describeSecurityGroupsOutput.SecurityGroups) == 1 {
				securityGroup := describeSecurityGroupsOutput.SecurityGroups[0]
				revokeSecurityGroupIngressInput := &ec2.RevokeSecurityGroupIngressInput{
					GroupId: securityGroup.GroupId,
					IpPermissions: []types.IpPermission{
						{
							IpProtocol: aws.String("-1"),
							UserIdGroupPairs: []types.UserIdGroupPair{{
								GroupId: securityGroup.GroupId,
								UserId:  aws.String(req.Deployment.Id),
							}},
						},
					},
				}
				_, err = ec2Client.RevokeSecurityGroupIngress(ctx, revokeSecurityGroupIngressInput)
				if err != nil {
					return nil, fmt.Errorf("unable to revoke default inbound security group rule: %w", err)
				}
				revokeSecurityGroupEgressInput := &ec2.RevokeSecurityGroupEgressInput{
					GroupId: securityGroup.GroupId,
					IpPermissions: []types.IpPermission{
						{
							IpProtocol: aws.String("-1"),
							IpRanges:   []types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
						},
					},
				}
				_, err = ec2Client.RevokeSecurityGroupEgress(ctx, revokeSecurityGroupEgressInput)
				if err != nil {
					return nil, fmt.Errorf("unable to revoke default outbound security group rule: %w", err)
				}
			}
		}

		// Get existing subnet
		subnetName := getSubnetName(req.Deployment.Namespace, region)
		describeSubnetsOutput, err := ec2Client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
			Filters: getDescribeFilter(req.Deployment.Namespace, subnetName),
		})
		if err != nil {
			return nil, fmt.Errorf("unable to get subnets: %w", err)
		}
		if len(describeSubnetsOutput.Subnets) == 1 {
			subnet = &describeSubnetsOutput.Subnets[0]
			if subnet.AvailabilityZone != nil && *subnet.AvailabilityZone != availabilityZone {
				return nil, fmt.Errorf("subnet is in a different availability zone than requested resource")
			}
		} else if len(describeSubnetsOutput.Subnets) == 0 {
			// Create subnet
			createSubnetInput := &ec2.CreateSubnetInput{
				VpcId:             vpc.VpcId,
				CidrBlock:         aws.String(*vpc.CidrBlock),
				AvailabilityZone:  aws.String(availabilityZone),
				TagSpecifications: getTagSpecificationsForCreateResource(req.Deployment.Namespace, subnetName, types.ResourceTypeSubnet),
			}
			createSubnetOutput, err := ec2Client.CreateSubnet(ctx, createSubnetInput)
			if err != nil {
				return nil, fmt.Errorf("unable to create subnet: %w", err)
			}
			subnet = createSubnetOutput.Subnet
		} else {
			return nil, fmt.Errorf("found more than one subnet")
		}

		// Set subnet ID for resource
		runInstancesInput.SubnetId = subnet.SubnetId
	} else {
		return nil, fmt.Errorf("found more than one VPC")
	}

	// Create security group
	securityGroupName := getSecurityGroupName(req.Deployment.Namespace, req.Name)
	createSecurityGroupInput := &ec2.CreateSecurityGroupInput{
		VpcId:             vpc.VpcId,
		GroupName:         aws.String(securityGroupName),
		Description:       aws.String("Security group for Paraglider"),
		TagSpecifications: getTagSpecificationsForCreateResource(req.Deployment.Namespace, securityGroupName, types.ResourceTypeSecurityGroup),
	}
	createSecurityGroupOutput, err := ec2Client.CreateSecurityGroup(ctx, createSecurityGroupInput)
	if err != nil {
		return nil, fmt.Errorf("unable to create security group: %w", err)
	}
	runInstancesInput.SecurityGroupIds = []string{*createSecurityGroupOutput.GroupId}

	// Remove default outbound rule from security group
	revokeSecurityGroupEgressInput := &ec2.RevokeSecurityGroupEgressInput{
		GroupId: createSecurityGroupOutput.GroupId,
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: aws.String("-1"),
				IpRanges:   []types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
			},
		},
	}
	_, err = ec2Client.RevokeSecurityGroupEgress(ctx, revokeSecurityGroupEgressInput)
	if err != nil {
		return nil, fmt.Errorf("unable to revoke default outbound security group rule: %w", err)
	}

	// Run instance
	runInstancesInput.TagSpecifications = getTagSpecificationsForCreateResource(req.Deployment.Namespace, req.Name, types.ResourceTypeInstance)
	runInstancesOutput, err := ec2Client.RunInstances(ctx, runInstancesInput)
	if err != nil {
		return nil, fmt.Errorf("unable to create instance: %w", err)
	}
	// Wait until instance is running
	instance := runInstancesOutput.Instances[0]
	instanceRunningWaiter := ec2.NewInstanceRunningWaiter(ec2Client)
	err = instanceRunningWaiter.Wait(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{*instance.InstanceId},
	}, 2*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("unable to wait for instance to be running: %w", err)
	}

	resp := &paragliderpb.CreateResourceResponse{
		Name: getNameTag(instance.Tags),
		Uri:  getInstanceArn(req.Deployment.Id, region, *instance.InstanceId),
		Ip:   *instance.PrivateIpAddress,
	}
	return resp, nil
}
