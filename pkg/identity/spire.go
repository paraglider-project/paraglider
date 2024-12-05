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

package identity

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/bramvdbogaerde/go-scp"
	"github.com/bramvdbogaerde/go-scp/auth"
	"golang.org/x/crypto/ssh"
)

const keyPath = "/.ibm/keys/paraglider-key"
const spireAgent = "/spire-1.10.0-linux-amd64-musl.tar.gz"

// AddAccessToResource adds a permitlist to
func AddAccessToResource() error {

}

func RevokeAccessToResource() error {

}

func generateJointToken(spiffeID string) string {
	cmd := exec.Command("kubectl", "exec", "-it", "spire-server-0", "-n", "spire-server", "-c", "spire-server", "--", "/opt/spire/bin/spire-server", "token", "generate", "-spiffeID", spiffeID)

	// Capture the output
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	// Run the command
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to execute command: %v\nOutput:\n%s", err, out.String())
	}

	// Output result
	output := out.String()
	fmt.Println("Command Output:", output)

	// Use regex to extract the token
	re := regexp.MustCompile(`Token:\s([a-f0-9\-]+)`)
	match := re.FindStringSubmatch(output)
	if len(match) < 2 {
		log.Fatalf("Failed to extract token from output")
	}
	token := match[1]

	fmt.Printf("Extracted Token: %s\n", token)
	return token
}

func copySpireBinary(user, ip string) {
	host := ip + ":22"

	config, err := auth.PrivateKey(user, os.Getenv("HOME")+keyPath, ssh.InsecureIgnoreHostKey())
	if err != nil {
		log.Fatalf("Failed to create private key: %v", err)
	}
	client := scp.NewClient(host, &config)

	if err := client.Connect(); err != nil {
		log.Fatalf("Failed to connect to remote server: %v", err)
	}
	defer client.Close()

	localFilePath := os.Getenv("HOME") + spireAgent
	remoteFilePath := "/tmp/" + spireAgent

	file, err := os.Open(localFilePath)
	if err != nil {
		log.Fatalf("Failed to open local file: %v", err)
	}
	defer file.Close()

	if err := client.CopyFile(context.Background(), file, remoteFilePath, "0644"); err != nil {
		log.Fatalf("Failed to copy file: %v", err)
	}

	fmt.Println("File copied successfully!")
}

func escapeSingleQuotes(input string) string {
	return strings.ReplaceAll(input, "'", "'\\''")
}

func createSpireConfig(jointToken string) string {
	spireConf := fmt.Sprintf(`agent {
	log_level = "DEBUG"
	trust_domain = "spire-server.local"
	server_address = "spire-server.spire-server.local"
	server_port = 443
	insecure_bootstrap = true
	join_token = "%s"
}
plugins {
	KeyManager "disk" {
		plugin_data {
			directory = "./"
		}
	}
	NodeAttestor "join_token" {
		plugin_data {}
	}
	WorkloadAttestor "unix" {
		plugin_data {}
	}
}`, jointToken)

	return escapeSingleQuotes(spireConf)

}

func setupSpireAgent(user, ip, spireServerIP, jointToken string) error {
	host := ip + ":22"

	key, err := os.ReadFile(os.Getenv("HOME") + keyPath)
	if err != nil {
		log.Fatalf("Unable to read private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("Unable to parse private key: %v", err)
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		log.Fatalf("Failed to dial: %s", err)
	}
	defer client.Close()

	// Add SPIRE server  to /etc/hosts
	lineToAdd := spireServerIP + " tornjak-backend.spire-server.local spire-server.spire-server.local oidc-discovery.spire-server.local tornjak-frontend.spire-server.local"

	cmd := fmt.Sprintf("echo '%s' | sudo tee -a /etc/hosts", lineToAdd)

	_, err = runCommand(client, cmd)
	if err != nil {
		log.Fatalf("Failed : %s", err)
	}

	output, err := runCommand(client, "cat /etc/hosts")
	if err != nil {
		log.Fatalf("Failed : %s", err)
	}
	fmt.Printf("Output:\n%s\n", output)

	copySpireBinary(user, ip)

	output, err = runCommand(client, "ls /tmp/spire*")
	if err != nil {
		log.Fatalf("Failed : %s", err)
	}
	fmt.Printf("Output:\n%s\n", output)

	_, err = runCommand(client, "tar zvxf /tmp/spire-1.10.0-linux-amd64-musl.tar.gz -C /tmp")
	if err != nil {
		log.Fatalf("Failed to untar: %s", err)
	}

	_, err = runCommand(client, "sudo cp -r /tmp/spire-1.10.0/. /opt/spire/")
	if err != nil {
		log.Fatalf("Failed to create directory /opt/spire: %s", err)
	}

	_, err = runCommand(client, "sudo ln -sf /opt/spire/bin/spire-agent /usr/bin/spire-agent")
	if err != nil {
		log.Fatalf("Failed to create a link to spire-agent: %s", err)
	}

	_, err = runCommand(client, "sudo mkdir -p /etc/spire/agent")
	if err != nil {
		log.Fatalf("Failed to create agent directory : %s", err)
	}

	// Define the remote command to create the file with sudo
	remoteFilePath := "/etc/spire/agent/main.conf"
	cmd = fmt.Sprintf("echo '%s' | sudo tee %s", createSpireConfig(jointToken), remoteFilePath)

	_, err = runCommand(client, cmd)
	if err != nil {
		log.Fatalf("Failed to write to file: %s", err)
	}

	// Start the SPIRE agent
	_, err = runCommand(client, "nohup spire-agent run -config /etc/spire/agent/main.conf &> spire-agent.log &")
	if err != nil {
		log.Fatalf("Failed to start SPIRE Agent: %s", err)
	}

	return nil
}

// runCommand executes a command on the remote server and returns the output
func runCommand(client *ssh.Client, cmd string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	var outputBuf bytes.Buffer
	session.Stdout = &outputBuf
	session.Stderr = &outputBuf

	if err := session.Run(cmd); err != nil {
		return "", fmt.Errorf("failed to run command: %w", err)
	}
	return outputBuf.String(), nil
}
