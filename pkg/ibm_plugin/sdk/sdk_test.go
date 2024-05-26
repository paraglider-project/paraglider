//go:build unit

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

package ibm

import (
	"testing"

	ibmCommon "github.com/paraglider-project/paraglider/pkg/ibm_plugin"
	"github.com/stretchr/testify/require"
)

var resourceGroupID = ibmCommon.GetIBMResourceGroupID()

const (
	testRegion = "us-east"
)

// TODO @praveingk: Expand tests of SDK functions

// run via: go test --tags=unit -run TestCleanup
// deletes all Paraglider's resources on IBM cloud
// Note: env var INVISINETS_TEST_PERSIST must be set to 1 for deployments to be terminated
func TestCleanup(t *testing.T) {
	err := TerminateParagilderDeployments(resourceGroupID, testRegion)
	require.NoError(t, err)
}

// Testing a function that returns true if cidr1 is a subset of cidr2,
// i.e. all ips in cidr1 exist within cidr2
func TestCIDRSubset(t *testing.T) {
	cidr1 := "10.10.10.8/29"  // 10.10.10.8 - 10.10.10.151
	cidr2 := "10.10.10.0/24"  // 10.10.10.0 - 10.10.10.255
	cidr3 := "192.50.64.0/17" // 192.50.0.0 - 192.50.127.255
	res1, err := IsCIDRSubset(cidr1, cidr2)
	require.NoError(t, err)
	res2, err := IsCIDRSubset(cidr2, cidr1)
	require.NoError(t, err)
	res3, err := IsCIDRSubset(cidr1, cidr1)
	require.NoError(t, err)
	res4, err := IsCIDRSubset(cidr3, cidr1)
	require.NoError(t, err)
	require.True(t, res1)
	require.False(t, res2)
	require.True(t, res3)
	require.False(t, res4)
}

// Testing a function that returns true if cidr1 and cidr2 overlap,
// i.e. the CIDRs share at least one ip
func TestCIDROverlap(t *testing.T) {
	cidr1 := "10.10.10.8/29"  // 10.10.10.8 - 10.10.10.151
	cidr2 := "10.10.10.0/24"  // 10.10.10.0 - 10.10.10.255
	cidr3 := "192.50.64.0/17" // 192.50.0.0 - 192.50.127.255
	res1, err := DoCIDROverlap(cidr1, cidr2)
	require.NoError(t, err)
	res2, err := DoCIDROverlap(cidr2, cidr1)
	require.NoError(t, err)
	res3, err := DoCIDROverlap(cidr1, cidr1)
	require.NoError(t, err)
	res4, err := DoCIDROverlap(cidr1, cidr3)
	require.NoError(t, err)
	res5, err := DoCIDROverlap(cidr2, cidr3)
	require.NoError(t, err)
	require.True(t, res1)
	require.True(t, res2)
	require.True(t, res3)
	require.False(t, res4)
	require.False(t, res5)
}
