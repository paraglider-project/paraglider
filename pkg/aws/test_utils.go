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
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
)

// Fake AWS parameters for testing
const (
	fakeAccountId                = "123456789"
	fakeInstanceName             = "fake-instance"
	fakeInstanceId               = fakeInstanceName + "-id"
	fakeInstancePrivateIpAddress = "10.0.0.1"
	fakeNamespace                = "fake-namespace"
	fakeRegion                   = "fake-region-1"
	fakeAvailabilityZone1        = fakeRegion + "a"
	fakeAvailabilityZone2        = fakeRegion + "b"
	fakeSecurityGroupId          = "fake-sg"
	fakeSubnetId                 = "fake-subnet-id"
	fakeVpcId                    = "fake-vpc-id"
	fakeVpcCidrBlock             = "10.0.0.0/16"
)

// Fake AWS parameters for testing
var (
	fakeSubnet = &types.Subnet{
		SubnetId:         aws.String(fakeSubnetId),
		AvailabilityZone: aws.String(fakeAvailabilityZone1),
	}
	fakeVpc = &types.Vpc{
		VpcId:     aws.String(fakeVpcId),
		CidrBlock: aws.String(fakeVpcCidrBlock),
	}
	fakeInstance = &types.Instance{
		InstanceId:       aws.String(fakeInstanceId),
		PrivateIpAddress: aws.String(fakeInstancePrivateIpAddress),
		Tags:             []types.Tag{{Key: aws.String("Name"), Value: aws.String(fakeInstanceName)}},
		State:            &types.InstanceState{Name: types.InstanceStateNameRunning},
	} // NOTE: this fakeInstance is only intended to be used as part of fakeServerState.
)

// fakeServerState represents the fake state of the AWS server during testing.
type fakeServerState struct {
	vpc    *types.Vpc
	subnet *types.Subnet
}

// fakeServerStateContextKey is an empty struct to be used as a key for context values.
// See SA1029 (https://staticcheck.dev/docs/checks#SA1029) on why we shouldn't use string keys.
type fakeServerStateContextKey struct{}
type requestContextKey struct{}

// fakeInitializeMiddleware is a middleware in the initialize step for faking AWS API calls during tests.
var fakeInitializeMiddleware = middleware.InitializeMiddlewareFunc("FakeInput", func(
	ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler,
) (
	out middleware.InitializeOutput, metadata middleware.Metadata, err error,
) {
	// Pass request parameters as part of context for deserialize middleware
	return next.HandleInitialize(context.WithValue(ctx, &requestContextKey{}, in.Parameters), in)
})

// fakeDeserializeMiddleware is a middleware in the deserialize step for faking AWS API calls during tests.
var fakeDeserializeMiddleware = middleware.DeserializeMiddlewareFunc("FakeOutput", func(
	ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler,
) (
	out middleware.DeserializeOutput, metadata middleware.Metadata, err error,
) {
	fakeServerState := ctx.Value(&fakeServerStateContextKey{}).(fakeServerState)
	switch ctx.Value(&requestContextKey{}).(type) {
	// VPCs
	case *ec2.CreateVpcInput:
		out.Result = &ec2.CreateVpcOutput{Vpc: fakeVpc}
	case *ec2.DescribeVpcsInput:
		describeVpcsOutput := &ec2.DescribeVpcsOutput{}
		if fakeServerState.vpc != nil {
			describeVpcsOutput.Vpcs = []types.Vpc{*fakeServerState.vpc}
		}
		out.Result = describeVpcsOutput
	case *ec2.CreateSubnetInput:
		out.Result = &ec2.CreateSubnetOutput{Subnet: fakeSubnet}
	case *ec2.DescribeSubnetsInput:
		describeSubnetsOutput := &ec2.DescribeSubnetsOutput{}
		if fakeServerState.subnet != nil {
			describeSubnetsOutput.Subnets = []types.Subnet{*fakeServerState.subnet}
		}
		out.Result = describeSubnetsOutput
	// Security Groups
	case *ec2.CreateSecurityGroupInput:
		out.Result = &ec2.CreateSecurityGroupOutput{GroupId: aws.String(fakeSecurityGroupId)}
	case *ec2.DescribeSecurityGroupsInput:
		out.Result = &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []types.SecurityGroup{{GroupId: aws.String(fakeSecurityGroupId)}}}
	case *ec2.RevokeSecurityGroupIngressInput:
		out.Result = &ec2.RevokeSecurityGroupIngressOutput{Return: aws.Bool(true)}
	case *ec2.RevokeSecurityGroupEgressInput:
		out.Result = &ec2.RevokeSecurityGroupEgressOutput{Return: aws.Bool(true)}
	// Instances
	case *ec2.RunInstancesInput:
		out.Result = &ec2.RunInstancesOutput{Instances: []types.Instance{*fakeInstance}}
	case *ec2.DescribeInstancesInput:
		out.Result = &ec2.DescribeInstancesOutput{Reservations: []types.Reservation{{Instances: []types.Instance{*fakeInstance}}}}
	}
	return
})

// setupTest sets up necessary fake components for a unit test.
func setupTest(fakeServerState fakeServerState) (context.Context, *awsClients, error) {
	// Set fake AWS credentials which are required for config
	os.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	// Load AWS config
	ctx := context.WithValue(context.TODO(), &fakeServerStateContextKey{}, fakeServerState)
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion("us-east-2"),
		config.WithAPIOptions([]func(*middleware.Stack) error{func(stack *middleware.Stack) error {
			err := stack.Initialize.Add(fakeInitializeMiddleware, middleware.Before)
			if err != nil {
				return err
			}
			err = stack.Deserialize.Add(fakeDeserializeMiddleware, middleware.Before)
			if err != nil {
				return err
			}
			return nil
		}}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to load config: %w", err)
	}

	// Create fake AWS clients
	fakeClients := &awsClients{}
	fakeClients.getOrCreateEc2Client(cfg)

	return ctx, fakeClients, nil
}

// getTestInstanceInputJson returns a test instance in a specified availability zone as JSON.
func getTestInstanceInputJson(availabilityZone string) ([]byte, error) {
	runInstanceInput := getTestInstanceInput(availabilityZone)
	runInstanceInputJson, err := json.Marshal(runInstanceInput)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal run instances input: %w", err)
	}
	return runInstanceInputJson, nil
}

// getTestInstanceInput returns a test instance in a specified availbility zone.
func getTestInstanceInput(availabilityZone string) *ec2.RunInstancesInput {
	return &ec2.RunInstancesInput{
		Placement: &types.Placement{
			AvailabilityZone: aws.String(availabilityZone),
		},
		MinCount:     aws.Int32(1),
		MaxCount:     aws.Int32(1),
		ImageId:      aws.String("ami-00db8dadb36c9815e"), // Amazon Linux 2023 AMI
		InstanceType: types.InstanceTypeT2Micro,
	}
}

// GetAwsAccountId returns the AWS account ID stored in an environment variable.
func GetAwsAccountId() string {
	accountId := os.Getenv("PARAGLIDER_AWS_ACCOUNT_ID")
	if accountId == "" {
		panic("Environment variable 'PARAGLIDER_AWS_ACCOUNT_ID' must be set")
	}
	return accountId
}

// SetupAwsTesting returns a namespace to be used for testing.
// Due to how teardown relies on the Paraglider namespace, the namespace should be unique between GitHub runs.
func SetupAwsTesting(testName string) string {
	ghRunNumber := testName + os.Getenv("GH_RUN_NUMBER")
	if ghRunNumber != "" {
		return testName + "-" + ghRunNumber
	}
	return testName
}

func TeardownAwsTesting(namespace string, region string) {
	if os.Getenv("PARAGLIDER_TEST_PERSIST") == "1" {
		return
	}
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		panic(fmt.Errorf("unable to load config: %w", err))
	}

	ec2Client := ec2.NewFromConfig(cfg)
	describeInstancesInput := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{{Name: aws.String("tag:Namespace"), Values: []string{namespace}}},
	}
	describeInstancesOutput, err := ec2Client.DescribeInstances(ctx, describeInstancesInput)
	if err != nil {
		panic(fmt.Errorf("Failed to describe instances: %w", err))
	}

	// Delete instances
	instanceIds := make([]string, 0)
	for _, reservation := range describeInstancesOutput.Reservations {
		for _, instance := range reservation.Instances {
			if instance.State.Name != types.InstanceStateNameTerminated {
				instanceIds = append(instanceIds, *instance.InstanceId)
			}
		}
	}
	if len(instanceIds) > 0 {
		terminateInstancesInput := &ec2.TerminateInstancesInput{
			InstanceIds: instanceIds,
		}
		_, err := ec2Client.TerminateInstances(ctx, terminateInstancesInput)
		if err != nil {
			panic(fmt.Errorf("failed to terminate instances: %w", err))
		}
		// Wait
		instanceTerminatedWaiter := ec2.NewInstanceTerminatedWaiter(ec2Client)
		err = instanceTerminatedWaiter.Wait(ctx, &ec2.DescribeInstancesInput{
			InstanceIds: instanceIds,
		}, 3*time.Minute)
		if err != nil {
			panic(fmt.Errorf("failed to wait for instances to terminate: %w", err))
		}
	}

	// Delete subnets
	describeSubnetsInput := &ec2.DescribeSubnetsInput{
		Filters: []types.Filter{{Name: aws.String("tag:Namespace"), Values: []string{namespace}}},
	}
	describeSubnetsOutput, err := ec2Client.DescribeSubnets(ctx, describeSubnetsInput)
	if err != nil {
		panic(fmt.Errorf("Failed to describe subnets: %w", err))
	}
	for _, subnet := range describeSubnetsOutput.Subnets {
		deleteSubnetInput := &ec2.DeleteSubnetInput{SubnetId: subnet.SubnetId}
		_, err := ec2Client.DeleteSubnet(ctx, deleteSubnetInput)
		if err != nil {
			panic(fmt.Errorf("Failed to delete subnet %s: %w", *subnet.SubnetId, err))
		}
	}

	// Delete security groups
	describeSecurityGroupsInput := &ec2.DescribeSecurityGroupsInput{
		Filters: []types.Filter{{Name: aws.String("tag:Namespace"), Values: []string{namespace}}},
	}
	describeSecurityGroupsOutput, err := ec2Client.DescribeSecurityGroups(ctx, describeSecurityGroupsInput)
	if err != nil {
		panic(fmt.Errorf("Failed to describe security groups: %w", err))
	}
	for _, securityGroup := range describeSecurityGroupsOutput.SecurityGroups {
		deleteSecurityGroupInput := &ec2.DeleteSecurityGroupInput{GroupId: securityGroup.GroupId}
		_, err := ec2Client.DeleteSecurityGroup(ctx, deleteSecurityGroupInput)
		if err != nil {
			panic(fmt.Errorf("Failed to delete security group %s: %w", *securityGroup.GroupId, err))
		}
	}

	// Delete VPCs
	describeVpcsInput := &ec2.DescribeVpcsInput{
		Filters: []types.Filter{{Name: aws.String("tag:Namespace"), Values: []string{namespace}}},
	}
	describeVpcsOutput, err := ec2Client.DescribeVpcs(ctx, describeVpcsInput)
	if err != nil {
		panic(fmt.Errorf("Failed to describe VPCs: %w", err))
	}
	for _, vpc := range describeVpcsOutput.Vpcs {
		deleteVpcInput := &ec2.DeleteVpcInput{
			VpcId: vpc.VpcId,
		}
		_, err := ec2Client.DeleteVpc(ctx, deleteVpcInput)
		if err != nil {
			panic(fmt.Errorf("Failed to delete VPC %s: %w", *vpc.VpcId, err))
		}
	}
}
