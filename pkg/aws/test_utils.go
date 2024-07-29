/*
Copyright 2024 The Paraglider Authors.

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
	fakeAvailabilityZone         = fakeRegion + "a"
	fakeSecurityGroupId          = "fake-sg"
	fakeSubnetId                 = "fake-subnet-id"
	fakeVpcId                    = "fake-vpc-id"
	fakeVpcCidrBlock             = "10.0.0.0/16"
)

// Fake AWS parameters for testing
var (
	fakeSubnet = &types.Subnet{
		SubnetId:         aws.String(fakeSubnetId),
		AvailabilityZone: aws.String(fakeAvailabilityZone),
	}
	fakeVpc = &types.Vpc{
		VpcId:     aws.String(fakeVpcId),
		CidrBlock: aws.String(fakeVpcCidrBlock),
	}
	fakeInstance = &types.Instance{
		InstanceId:       aws.String(fakeInstanceId),
		PrivateIpAddress: aws.String(fakeInstancePrivateIpAddress),
		Tags:             []types.Tag{{Key: aws.String("Name"), Value: aws.String(fakeInstanceName)}},
	} // NOTE: this fakeInstance is only intended to be used as part of fakeServerState.
)

// fakeServerState represents the fake state of the AWS server during testing.
type fakeServerState struct {
	instance *types.Instance
	vpc      *types.Vpc
	subnet   *types.Subnet
}

// fakeInitializeMiddleware is a middleware in the initialize step for faking AWS API calls during tests.
var fakeInitializeMiddleware = middleware.InitializeMiddlewareFunc("FakeInput", func(
	ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler,
) (
	out middleware.InitializeOutput, metadata middleware.Metadata, err error,
) {
	// Pass request parameters as part of context for deserialize middleware
	return next.HandleInitialize(context.WithValue(ctx, "request", in.Parameters), in)
})

// fakeDeserizliaeMiddle is a middleware in the deserialize step for faking AWS API calls during tests.
var fakeDeserializeMiddleware = middleware.DeserializeMiddlewareFunc("FakeOutput", func(
	ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler,
) (
	out middleware.DeserializeOutput, metadata middleware.Metadata, err error,
) {
	fakeServerState := ctx.Value("fakeServerState").(fakeServerState)
	switch ctx.Value("request").(type) {
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
	case *ec2.RevokeSecurityGroupEgressInput:
		out.Result = &ec2.RevokeSecurityGroupEgressOutput{Return: aws.Bool(true)}
	// Instances
	case *ec2.RunInstancesInput:
		out.Result = &ec2.RunInstancesOutput{Instances: []types.Instance{*fakeInstance}}
	}
	return
})

// setupTest sets up necessary fake components for a unit test.
func setupTest(fakeServerState fakeServerState) (context.Context, *awsClients, error) {
	// Load AWS config
	ctx := context.WithValue(context.TODO(), "fakeServerState", fakeServerState)
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion("us-east-2"),
		config.WithAPIOptions([]func(*middleware.Stack) error{func(stack *middleware.Stack) error {
			stack.Initialize.Add(fakeInitializeMiddleware, middleware.Before)
			stack.Deserialize.Add(fakeDeserializeMiddleware, middleware.Before)
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
		ImageId:      aws.String("ami-00db8dadb36c9815e"),
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
