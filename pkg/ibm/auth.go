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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"golang.org/x/crypto/ssh"

	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

const keyType = "key"

// creates ssh keys and registers them if absent.
// returns key id of registered public key.
func (c *CloudClient) setupAuth() (string, error) {
	var keyID string
	keyNameToRegister := generateResourceName(keyType)

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
func (c *CloudClient) getKeyByPublicKey(publicKeyData string) (string, error) {
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

// GetAPIKey returns API KEY ID defined in environment variable
func getAPIKey() (string, error) {
	apiKey := os.Getenv("PARAGLIDER_IBM_API_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("environment variable 'PARAGLIDER_IBM_API_KEY' is required for authentication")
	}
	return apiKey, nil
}

// returns a user authenticator object to authorize IBM cloud services
func getAuthenticator() (*core.IamAuthenticator, error) {
	apiKey, err := getAPIKey()
	if err != nil {
		return nil, err
	}
	return &core.IamAuthenticator{ApiKey: apiKey}, err
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
	_, err = publicKeyFile.WriteString(pubKeyStr)
	if err != nil {
		return "", err
	}

	utils.Log.Println("Created SSH keys at ", filepath.Dir(privateKeyPath))
	return pubKeyStr, nil
}
