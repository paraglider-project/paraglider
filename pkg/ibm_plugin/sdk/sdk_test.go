//go:build ibm

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

package ibm

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/require"
)

var vpcID string
var vpcRegion string

func init() {
	flag.StringVar(&vpcID, "vpcID", "", "vpc id to terminate")
	flag.StringVar(&vpcRegion, "vpcRegion", "", "vpc region")
}

const (
	testResGroupName = "invisinets"
	testRegion       = "us-east"
)

// run via: go test -run TestTerminateVPC -vpcID=value -vpcRegion=value
func TestTerminateVPC(t *testing.T) {
	if vpcID == "" || vpcRegion == "" {
		println("(TestTerminateVPC skipped - missing arguments)")
		t.Skip("TestTerminateVPC skipped - missing arguments")
	}
	cloudClient, err := NewIBMCloudClient(testResGroupName, vpcRegion)
	require.NoError(t, err)
	err = cloudClient.TerminateVPC(vpcID)
	require.NoError(t, err)
}

// Testing a function that returns true if cidr1 is a subset of cidr2,
// i.e. all ips in cidr1 exist within cidr2
func TestCidrSubset(t *testing.T) {
	cidr1 := "10.10.10.8/29"  // 10.10.10.8 - 10.10.10.151
	cidr2 := "10.10.10.0/24"  // 10.10.10.0 - 10.10.10.255
	cidr3 := "192.50.64.0/17" // 192.50.0.0 - 192.50.127.255
	res1, err := IsCidrSubset(cidr1, cidr2)
	require.NoError(t, err)
	res2, err := IsCidrSubset(cidr2, cidr1)
	require.NoError(t, err)
	res3, err := IsCidrSubset(cidr1, cidr1)
	require.NoError(t, err)
	res4, err := IsCidrSubset(cidr3, cidr1)
	require.NoError(t, err)
	require.True(t, res1)
	require.False(t, res2)
	require.True(t, res3)
	require.False(t, res4)
}

// Testing a function that returns true if cidr1 and cidr2 overlap,
// i.e. the CIDRs share at least one ip
func TestCidrOverlap(t *testing.T) {
	cidr1 := "10.10.10.8/29"  // 10.10.10.8 - 10.10.10.151
	cidr2 := "10.10.10.0/24"  // 10.10.10.0 - 10.10.10.255
	cidr3 := "192.50.64.0/17" // 192.50.0.0 - 192.50.127.255
	res1, err := DoCidrOverlap(cidr1, cidr2)
	require.NoError(t, err)
	res2, err := DoCidrOverlap(cidr2, cidr1)
	require.NoError(t, err)
	res3, err := DoCidrOverlap(cidr1, cidr1)
	require.NoError(t, err)
	res4, err := DoCidrOverlap(cidr1, cidr3)
	require.NoError(t, err)
	res5, err := DoCidrOverlap(cidr2, cidr3)
	require.NoError(t, err)
	require.True(t, res1)
	require.True(t, res2)
	require.True(t, res3)
	require.False(t, res4)
	require.False(t, res5)
}
