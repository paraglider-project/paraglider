package ibm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/IBM/go-sdk-core/v5/core"
	utils "github.com/NetSys/invisinets/pkg/utils"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// indicate the type of tagged resource to fetch
type TaggedResourceType string
type InstanceProfile string

const (
	VPC               TaggedResourceType = "vpc"
	SUBNET            TaggedResourceType = "subnet"
	VM                TaggedResourceType = "instance"
	SG                TaggedResourceType = "security-group"
	credentialsPath   string             = ".ibm/credentials.yaml"
	publicSSHKey                         = ".ibm/keys/invisinets-key.pub"
	privateSSHKey                        = ".ibm/keys/invisinets-key"
	defaultImage                         = "ibm-ubuntu-22-04"
	imageArchitecture                    = "amd64"
	ResourcePrefix                       = "invisinets"
	LowCPU            InstanceProfile    = "bx2-2x8"
	HighCPU           InstanceProfile    = "bx2-8x32"
	GPU               InstanceProfile    = "gx2-8x64x1v100"
)

// Credentials extracted from local credential file
type Credentials struct {
	APIKey          string `yaml:"iam_api_key"`
	ResourceGroupID string `yaml:"resource_group_id"`
}

// Used to extend query for tagged resources
type ResourceQuery struct {
	Region string
	Zone   string
}

type SecurityGroupRule struct {
	ID         string // Unique identifier of this rule
	SgID       string // Unique ID of the security group to which this rule belongs
	Protocol   string // IP protocol that this rules applies to
	Remote     string // What this rule applies to (IP or CIDR block)
	RemoteType string // Type of remote, can be "IP", "CIDR", or "SG"
	PortMin    int64  // First port of the range to which this rule applies (only available for TCP/UDP rules), -1 means all ports
	PortMax    int64  // Last port of the range to which this rule applies (only available for TCP/UDP rules), -1 means all ports
	IcmpType   int64  // ICMP Type for the rule (only available for ICMP rules), -1 means all types
	IcmpCode   int64  // ICMP Code for the rule (only available for ICMP rules), -1 means all codes
	Egress     bool   // The rule affects to outbound traffic (true) or inbound (false)
}

var Regions = [10]string{"us-south", "us-east", "eu-de", "eu-gb", "eu-es", "ca-tor", "au-syd",
	"br-sao", "jp-osa", "jp-tok"}

// returns "Credentials" object loaded from "credentialsPath"
func get_ibm_cred() (Credentials, error) {
	var credentials Credentials

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return credentials, fmt.Errorf("failed to generate home path: \n%v", err)
	}
	data, err := os.ReadFile(filepath.Join(homeDir, credentialsPath))
	if err != nil {
		return credentials, fmt.Errorf("failed to read credential file:\n%v", err)
	}
	err = yaml.Unmarshal(data, &credentials)
	if err != nil {
		return credentials, fmt.Errorf("failed to unmarshal credential file:\n%v", err)
	}

	return credentials, nil
}

// returns local public key contents if exists, else
// creates ssh key pair in .ibm/keys.
func getLocalPubKey() (string, error) {
	var publicKeyData string
	homeDir, err := os.UserHomeDir()
	if err != nil {
		utils.Log.Println("Failed to generate home path: \n", err)
		return "", err
	}

	pubKeyPath := filepath.Join(homeDir, publicSSHKey)
	err = os.MkdirAll(filepath.Dir(filepath.Join(homeDir, publicSSHKey)), 0700)
	if err != nil {
		utils.Log.Println("Failed to create ssh key folder\n", err)
		return "", err
	}

	//check if ssh keys exist
	_, err = os.Stat(pubKeyPath)

	if err != nil {
		if os.IsNotExist(err) {
			// local ssh keys do not exist, create them.
			data, keyGenErr := createSSHKeys(filepath.Join(homeDir, privateSSHKey))
			publicKeyData = data
			if keyGenErr != nil {
				utils.Log.Println("Failed to generate ssh keys.\nError:", keyGenErr)
				return "", err
			}
		} else { // Non expected error
			utils.Log.Println("Failed to verify if ssh keys exist", err)
			return "", err
		}
	} else { // ssh keys exist
		data, err := os.ReadFile(pubKeyPath)
		publicKeyData = string(data)
		if err != nil { // failed to read public ssh key data
			utils.Log.Println(err)
			return "", err
		}
	}
	return publicKeyData, nil
}

// creates public and private key at specified location.
// returns public key data.
func createSSHKeys(privateKeyPath string) (string, error) {
	if privateKeyPath == "" {
		return "", fmt.Errorf("private key path is missing")
	}
	// creates local private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", err
	}
	privateKeyFile, err := os.OpenFile(privateKeyPath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return "", err
	}
	defer privateKeyFile.Close()
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return "", err
	}

	// creates local public key based on private key
	publicRsaKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", err
	}
	pubKeyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicRsaKey)))

	publicKeyFile, err := os.OpenFile(privateKeyPath+".pub", os.O_RDWR|os.O_CREATE, 0655)
	if err != nil {
		return "", err
	}
	defer publicKeyFile.Close()
	publicKeyFile.WriteString(pubKeyStr)

	utils.Log.Println("Created SSH keys at ", filepath.Dir(privateKeyPath))
	return pubKeyStr, nil
}

// returns true if a slice contains an item
func DoesSliceContain[T comparable](slice []T, target T) bool {
	for _, val := range slice {
		if val == target {
			return true
		}
	}
	return false
}

// returns true if region is a valid IBM region
func IsRegionValid(region string) bool {
	return DoesSliceContain(Regions[:], region)
}

// returns url of IBM region
func endpointURL(region string) string {
	return fmt.Sprintf("https://%s.iaas.cloud.ibm.com/v1", region)
}

// returns zones of region
func GetZonesOfRegion(region string) ([]string, error) {
	zonesPerRegion := 3
	if !IsRegionValid(region) {
		return nil, fmt.Errorf("region %v isn't valid", region)
	}
	res := make([]string, zonesPerRegion)
	for i := 0; i < zonesPerRegion; i++ {
		res[i] = region + "-" + fmt.Sprint(i+1)
	}
	return res, nil
}

// returns region of zone
func Zone2Region(zone string) (string, error) {
	lastDashIndex := strings.LastIndex(zone, "-")

	if lastDashIndex == -1 {
		return "", fmt.Errorf("zone: %v isn't in a valid IBM zone format", zone)
	}
	regionVal := zone[:lastDashIndex]

	for _, region := range Regions {
		if regionVal == region {
			return regionVal, nil
		}
	}
	return "", fmt.Errorf("zone specified: %v not valid", zone)
}

// returns ID of resource based on its CRN
func CRN2ID(crn string) string {
	index := strings.LastIndex(crn, ":")
	if index == -1 {
		utils.Log.Fatalf("CRN: %v isn't of valid format", crn)
	}
	return crn[index+1:]
}

// returns unique invisinets resource name
func GenerateResourceName(name string) string {
	return fmt.Sprintf("%v-%v-%v", ResourcePrefix, name, uuid.New().String()[:8])
}

// returns false if cidr blocks don't share a single ip,
// i.e. they don't overlap.
func DoCidrOverlap(cidr1, cidr2 string) (bool, error) {
	netCIDR1, err := netip.ParsePrefix(cidr1)
	if err != nil {
		return true, err
	}
	netCIDR2, err := netip.ParsePrefix(cidr2)
	if err != nil {
		return true, err
	}
	if netCIDR2.Overlaps(netCIDR1) {
		return true, nil
	}

	return false, nil
}

// returns true if cidr1 is a subset (including equal) to cidr2
func IsCidrSubset(cidr1, cidr2 string) (bool, error) {
	firstIP1, netCidr1, err := net.ParseCIDR(cidr1)
	// ParseCIDR() example from Docs: for CIDR="192.0.2.1/24"
	// IP=192.0.2.1 and network mask 192.0.2.0/24 are returned
	if err != nil {
		return false, err
	}

	_, netCidr2, err := net.ParseCIDR(cidr2)
	if err != nil {
		return false, err
	}
	// number of significant bits in the subnet mask
	maskSize1, _ := netCidr1.Mask.Size()
	maskSize2, _ := netCidr2.Mask.Size()
	//cidr1 is a subset of cidr2 if the first user ip of cidr1 within cidr2
	// and the network mask of cider1 is no smaller than that of cidr2, as
	// fewer bits is left for user address space.
	return netCidr2.Contains(firstIP1) && maskSize1 >= maskSize2, nil
}

// returns true if remote is contained in the CIDR's IP range.
// remote could be either an IP or a CIDR block.
func IsRemoteInCidr(remote, cidr string) (bool, error) {
	remoteType, err := GetRemoteType(remote)
	if err != nil {
		return false, err
	}
	if remoteType == "IP" {
		_, netCidr, err := net.ParseCIDR(cidr)
		if err != nil {
			return false, err
		}
		netIP := net.ParseIP(remote)
		if netIP == nil {
			return false, fmt.Errorf("ip %v isn't a valid IP address", remote)
		}
		return netCidr.Contains(netIP), nil
	}
	return IsCidrSubset(remote, cidr)
}

// splits given cidr 3 ways, so the last cidr is as large as the first 2 combined:
// x.x.x.x/y+2, x.x.64.x/y+2, x.x.128.x/y+1 for cider=x.x.x.x/y.
func SplitCidr3Ways(cidr string) ([]string, error) {
	cidrParts := strings.Split(cidr, "/")
	netmask, err := strconv.Atoi(cidrParts[1])
	if err != nil {
		return nil, err
	}
	netmaskZone1Zone2 := netmask + 2
	netmaskZone3 := netmask + 1
	ip := cidrParts[0]
	ipOctets := strings.Split(ip, ".")
	zone2Octets := make([]string, 4)
	copy(zone2Octets, ipOctets)
	zone2Octets[2] = "64"
	ipZone2 := strings.Join(zone2Octets, ".")
	zone3Octets := make([]string, 4)
	copy(zone3Octets, ipOctets)
	zone3Octets[2] = "128"
	ipZone3 := strings.Join(zone3Octets, ".")
	return []string{
		fmt.Sprintf("%s/%d", ip, netmaskZone1Zone2),
		fmt.Sprintf("%s/%d", ipZone2, netmaskZone1Zone2),
		fmt.Sprintf("%s/%d", ipZone3, netmaskZone3),
	}, nil
}

// returns IBM specific keyword returned by vpc1 SDK,
// indicating the type of remote an SG rule permits
func GetRemoteType(remote string) (string, error) {
	ip := net.ParseIP(remote)
	if ip != nil {
		return "IP", nil
	}
	_, _, err := net.ParseCIDR(remote)
	if err == nil {
		return "CIDR", nil
	}
	return "", fmt.Errorf("remote %v isn't a CIDR/IP", remote)
}

// returns IBM specific keyword returned by vpc1 SDK,
// indicating the traffic direction an SG rule permits
func getEgressDirection(egress bool) *string {
	if egress {
		return core.StringPtr("outbound")
	} else {
		return core.StringPtr("inbound")
	}
}

// returns true if two given structs of the same type have matching fields values
// on all types except those listed in fieldsToExclude
func AreStructsEqual(s1, s2 interface{}, fieldsToExclude []string) bool {
	v1 := reflect.ValueOf(s1)
	v2 := reflect.ValueOf(s2)

	if v1.Type() != v2.Type() {
		return false
	}

	for i := 0; i < v1.NumField(); i++ {
		fieldName := v1.Type().Field(i).Name
		if DoesSliceContain(fieldsToExclude, fieldName) {
			continue
		}

		if !reflect.DeepEqual(v1.Field(i).Interface(), v2.Field(i).Interface()) {
			return false
		}
	}
	return true
}
