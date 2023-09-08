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

// run via: go test -run TestTerminateVPC -vpcID=value -vpcRegion=value
func TestTerminateVPC(t *testing.T) {
	if vpcID == "" || vpcRegion == "" {
		println("(TestTerminateVPC skipped - missing arguments)")
		t.Skip("TestTerminateVPC skipped - missing arguments")
	}
	cloudClient, err := NewIbmCloudClient(vpcRegion)
	require.NoError(t, err)
	err = cloudClient.TerminateVPC(vpcID)
	require.NoError(t, err)
}

// Testing a function that returns true if cidr1 is a subset of cidr2,
// i.e. all ips in cidr1 exist within cidr2
func TestCiderSubset(t *testing.T) {
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
func TestCiderOverlap(t *testing.T) {
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
