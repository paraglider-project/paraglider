package ibm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/IBM/vpc-go-sdk/vpcv1"
	utils "github.com/NetSys/invisinets/pkg/utils"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// Credentials extracted from local credential file
type Credentials struct {
	APIKey          string `yaml:"iam_api_key"`
	ResourceGroupID string `yaml:"resource_group_id"`
}

// creates ssh keys and registers them if absent.
// returns key id of registered public key.
func (c *IBMCloudClient) setupAuthentication() (string, error) {
	var keyID string
	keyNameToRegister := GenerateResourceName("key")

	publicKeyData, err := getLocalPubKey()
	if err != nil {
		return "", err
	}
	if publicKeyData == "" {
		return "", fmt.Errorf("empty data returned for public key")
	}
	// Register SSH key unless already registered
	result, _, err := c.vpcService.CreateKey(&vpcv1.CreateKeyOptions{
		Name:          &keyNameToRegister,
		PublicKey:     &publicKeyData,
		ResourceGroup: c.resourceGroup,
	})

	if err != nil {
		if strings.Contains(err.Error(), "fingerprint already exists") {
			utils.Log.Println("Reusing registered local SSH key")
			keyID, err = c.getKeyByPublicKey(publicKeyData)
			if err != nil {
				utils.Log.Println("Failed to reuse registered local SSH key")
				return "", err
			}
		} else {
			utils.Log.Println("Failed to register SSH key\n", err)
			return "", err
		}

	} else {
		keyID = *result.ID
	}
	return keyID, nil
}

// returns key id of a registered key matching the public key data.
func (c *IBMCloudClient) getKeyByPublicKey(publicKeyData string) (string, error) {
	var resultLimit int64 = 100 // number of results per API response
	publicKeyData = strings.TrimSpace(publicKeyData)
	listKeysOptions := &vpcv1.ListKeysOptions{Limit: &resultLimit}
	// TODO introduce pagination in case user has more then 100 keys in selected region

	keys, _, err := c.vpcService.ListKeys(listKeysOptions)
	if err != nil {
		utils.Log.Println(err)
		return "", nil
	}

	for _, key := range keys.Keys {
		if *key.PublicKey == publicKeyData {
			utils.Log.Println("Found matching registered key:", *key.ID)
			return *key.ID, nil
		}
	}
	return "", fmt.Errorf(`no registered key matching the specified public
			 key was found`)
}

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
