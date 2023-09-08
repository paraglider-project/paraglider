package ibm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

var regions = [10]string{"us-south", "us-east", "eu-de", "eu-gb", "eu-es", "ca-tor", "au-syd",
	"br-sao", "jp-osa", "jp-tok"}

func get_ibm_cred() []string {
	yamlMap := make(map[string]string)
	credKeys := []string{"iam_api_key", "resource_group_id"}
	credValues := make([]string, 0, 2)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalln("Failed to generate home path: \n", err)
	}
	data, err := os.ReadFile(filepath.Join(homeDir, credentialsPath))
	if err != nil {
		log.Fatalln("Failed to read credential file:\n ", err)
	}

	// Unmarshal the YAML string into the data map
	err = yaml.Unmarshal(data, &yamlMap)
	if err != nil {
		log.Fatalln("Failed to unmarshal credential file into a map:\n ", err)
	}
	for _, credKey := range credKeys {
		credVal, ok := yamlMap[credKey]
		if !ok {
			log.Fatalln("Missing IBM credential field: ", credVal)
		}
		credValues = append(credValues, credVal)

	}
	return credValues
}

func CreateSSHKeys(privateKeyPath string) (string, error) {
	if privateKeyPath == "" {
		return "", fmt.Errorf("keyName is empty")
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", err
	}

	privateKeyFile, err := os.Create(privateKeyPath)
	if err != nil {
		return "", err
	}
	defer privateKeyFile.Close()

	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return "", err
	}

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

	log.Println("Created SSH keys at ", filepath.Dir(privateKeyPath))
	return pubKeyStr, nil
}

func CRN2ID(crn string) string {
	index := strings.Index(crn, "vpc:")
	if index == -1 {
		log.Fatalf("CRN: %v isn't of valid format", crn)
	}
	return crn[index+4:]
}

func Zone2Region(zone string) (string, error) {
	lastDashIndex := strings.LastIndex(zone, "-")

	if lastDashIndex == -1 {
		log.Fatalf("string: %v isn't in a valid IBM zone format", zone)
	}
	regionVal := zone[:lastDashIndex]
	for _, region := range regions {
		if regionVal == region {
			return regionVal, nil
		}
	}
	return "", fmt.Errorf("zone specified: %v not valid", zone)
}

func GenerateResourceName(name string) string {
	return fmt.Sprintf("%v-%v-%v", ResourcePrefix, name, uuid.New().String()[:8])
}

func endpointURL(region string) string {
	return fmt.Sprintf("https://%s.iaas.cloud.ibm.com/v1", region)
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
	firstIP1, networkMask1, err := net.ParseCIDR(cidr1)
	// ParseCIDR() example from Docs: for CIDR="192.0.2.1/24"
	// IP=192.0.2.1 and network mask 192.0.2.0/24 are returned
	if err != nil {
		return false, err
	}

	_, networkMask2, err := net.ParseCIDR(cidr2)
	if err != nil {
		return false, err
	}
	// number of significant bits in the subnet mask
	maskSize1, _ := networkMask1.Mask.Size()
	maskSize2, _ := networkMask2.Mask.Size()
	//cidr1 is a subset of cidr2 if the first user ip of cidr1 within cidr2
	// and the network mask of cider1 is no smaller than that of cidr2, as
	// fewer bits is left for user address space.
	return networkMask2.Contains(firstIP1) && maskSize1 >= maskSize2, nil
}
