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
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const (
	paragliderPrefix         = "para"    // Prefix for all resources
	defaultSecurityGroupName = "default" // Default security group name as set by AWS
)

// getDescribeFilter returns a filter for a resource to use for getting (e.g., Describe...).
func getDescribeFilter(namespace string, name string) []types.Filter {
	return []types.Filter{
		{Name: aws.String("tag:Name"), Values: []string{name}},
		{Name: aws.String("tag:Namespace"), Values: []string{namespace}},
	}
}

// getCreateTagSpecifications returns tag specifications for a resource to use for creating (e.g., Create...).
func getCreateTagSpecifications(namespace string, name string, resourceType types.ResourceType) []types.TagSpecification {
	return []types.TagSpecification{
		{
			ResourceType: resourceType,
			Tags: []types.Tag{
				{Key: aws.String("Name"), Value: aws.String(name)},
				{Key: aws.String("Namespace"), Value: aws.String(namespace)},
			},
		},
	}
}

// getNamespacePrefix returns the prefix for all resources within a specific namespace.
func getNamespacePrefix(namespace string) string {
	return paragliderPrefix + "-" + namespace
}

// getVpcName returns the name of a VPC in namespace and region.
func getVpcName(namespace string, region string) string {
	return fmt.Sprintf("%s-%s-%s", getNamespacePrefix(namespace), region, "vpc")
}

// getSubnetName returns the name of a subnet in a namespace and region.
func getSubnetName(namespace string, region string) string {
	return fmt.Sprintf("%s-%s-%s", getNamespacePrefix(namespace), region, "subnet")
}

// getSecurityGroupName returns the name of a security group for instanceName in namespace.
func getSecurityGroupName(namespace string, instanceName string) string {
	// Can't use an immutable field like ID since security group needs to be created before instance creation.
	return fmt.Sprintf("%s-%s-%s", getNamespacePrefix(namespace), instanceName, "sg")
}

// getInstanceArn returns the ARN of an instance.
func getInstanceArn(accountId string, region string, instanceId string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, accountId, instanceId)
}
