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

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/paraglider-project/paraglider/pkg/orchestrator"
	"github.com/paraglider-project/paraglider/pkg/orchestrator/config"
	"github.com/paraglider-project/paraglider/pkg/paragliderpb"
	"github.com/paraglider-project/paraglider/pkg/tag_service/tagservicepb"
	"github.com/paraglider-project/paraglider/pkg/utils"
)

type ParagliderControllerClient interface {
	GetPermitList(namespace string, cloud string, resourceName string) ([]*paragliderpb.PermitListRule, error)
	AddPermitListRules(namespace string, cloud string, resourceName string, rules []*paragliderpb.PermitListRule) error
	DeletePermitListRules(namespace string, cloud string, resourceName string, rules []string) error
	CreateResource(namespace string, cloud string, resourceName string, resource *paragliderpb.ResourceDescriptionString) (map[string]string, error)
	AttachResource(namespace string, cloud string, resource *orchestrator.ResourceID) (map[string]string, error)
	CheckResource(namespace string, cloud string, resourceName string) (map[int32]string, error)
	FixResource(namespace string, cloud string, resourceName string) (map[int32]string, error)
	AddPermitListRulesTag(tag string, rules []*paragliderpb.PermitListRule) error
	DeletePermitListRulesTag(tag string, rules []string) error
	GetTag(tag string) (*tagservicepb.TagMapping, error)
	ResolveTag(tag string) ([]*tagservicepb.TagMapping, error)
	SetTag(tag string, tagMapping *tagservicepb.TagMapping) error
	DeleteTag(tag string) error
	DeleteTagMembers(tag string, members []string) error
	ListNamespaces() (map[string][]config.CloudDeployment, error)
}

type Client struct {
	ParagliderControllerClient
	ControllerAddress string
}

// Proccess the response from the controller and return the body
func (c *Client) processResponse(resp *http.Response) ([]byte, error) {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return bodyBytes, fmt.Errorf("Request failed with status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return bodyBytes, nil
}

// Send a request to the controller and return the response body
func (c *Client) sendRequest(url string, method string, body io.Reader) ([]byte, error) {
	client := &http.Client{}

	url = c.ControllerAddress + url

	// Prepend with http to make net/http happy
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	bodyBytes, err := c.processResponse(resp)

	return bodyBytes, err
}

// Get a permit list for a resource
func (c *Client) GetPermitList(namespace string, cloud string, resourceName string) ([]*paragliderpb.PermitListRule, error) {
	path := fmt.Sprintf(orchestrator.GetFormatterString(orchestrator.GetPermitListRulesURL), namespace, cloud, resourceName)

	respBytes, err := c.sendRequest(path, http.MethodGet, nil)
	if err != nil {
		return nil, err
	}

	var rules []*paragliderpb.PermitListRule
	err = json.Unmarshal(respBytes, &rules)
	if err != nil {
		return nil, err
	}

	return rules, nil
}

// Add permit list rules to a resource
func (c *Client) AddPermitListRules(namespace string, cloud string, resourceName string, rules []*paragliderpb.PermitListRule) error {
	path := fmt.Sprintf(orchestrator.GetFormatterString(orchestrator.AddPermitListRulesURL), namespace, cloud, resourceName)

	reqBody, err := json.Marshal(rules)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(path, http.MethodPost, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	return nil
}

// Delete permit list rules from a resource
func (c *Client) DeletePermitListRules(namespace string, cloud string, resourceName string, rules []string) error {
	path := fmt.Sprintf(orchestrator.GetFormatterString(orchestrator.DeletePermitListRulesURL), namespace, cloud, resourceName)

	reqBody, err := json.Marshal(rules)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(path, http.MethodPost, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	return nil
}

// Create a resource
func (c *Client) CreateResource(namespace string, cloud string, resourceName string, resource *paragliderpb.ResourceDescriptionString) (map[string]string, error) {
	path := fmt.Sprintf(orchestrator.GetFormatterString(orchestrator.CreateResourcePUTURL), namespace, cloud, resourceName)

	reqBody, err := json.Marshal(resource)
	if err != nil {
		return nil, err
	}

	response, err := c.sendRequest(path, http.MethodPut, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	resourceDict := map[string]string{}
	err = json.Unmarshal(response, &resourceDict)
	if err != nil {
		return nil, err
	}

	return resourceDict, nil
}

// Attach a resource
func (c *Client) AttachResource(namespace string, cloud string, resource *orchestrator.ResourceID) (map[string]string, error) {
	path := fmt.Sprintf(orchestrator.GetFormatterString(orchestrator.CreateOrAttachResourcePOSTURL), namespace, cloud)

	reqBody, err := json.Marshal(resource)
	if err != nil {
		return nil, err
	}

	response, err := c.sendRequest(path, http.MethodPost, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to attach resource: %w", err)
	}

	resourceDict := map[string]string{}
	err = json.Unmarshal(response, &resourceDict)
	if err != nil {
		return nil, err
	}

	return resourceDict, nil
}

func (c *Client) CheckResource(namespace string, cloud string, resourceName string) (map[int32]string, error) {
	path := fmt.Sprintf(orchestrator.GetFormatterString(orchestrator.CheckResourceURL), namespace, cloud, resourceName)
	respBytes, err := c.sendRequest(path, http.MethodGet, nil)
	if err != nil {
		return nil, err
	}

	// Get the errors in a map
	resp := map[int32]string{}
	err = json.Unmarshal(respBytes, &resp)
	if err != nil {
		utils.Log.Println("Error in unmarshalling response:", err)
		return nil, err
	}

	return resp, nil
}

func (c *Client) FixResource(namespace string, cloud string, resourceName string) (map[int32]string, error) {
	path := fmt.Sprintf(orchestrator.GetFormatterString(orchestrator.FixResourceURL), namespace, cloud, resourceName)
	respBytes, err := c.sendRequest(path, http.MethodPost, nil)
	if err != nil {
		return nil, err
	}

	// Bind the fixed errors to a map
	resp := map[int32]string{}
	err = json.Unmarshal(respBytes, &resp)
	if err != nil {
		utils.Log.Println("Error in unmarshalling response:", err)
		return nil, err
	}

	return resp, nil
}

// Add permit list rules to a tag
func (c *Client) AddPermitListRulesTag(tag string, rules []*paragliderpb.PermitListRule) error {
	path := fmt.Sprintf(orchestrator.GetFormatterString(orchestrator.RuleOnTagURL), tag)

	reqBody, err := json.Marshal(rules)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(path, http.MethodPost, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	return nil
}

// Remove permit list rules to a tag
func (c *Client) DeletePermitListRulesTag(tag string, rules []string) error {
	path := fmt.Sprintf(orchestrator.GetFormatterString(orchestrator.RuleOnTagURL), tag)

	reqBody, err := json.Marshal(rules)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(path, http.MethodDelete, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	return nil
}

// Get the members of a tag
func (c *Client) GetTag(tag string) (*tagservicepb.TagMapping, error) {
	path := fmt.Sprintf(orchestrator.GetFormatterString(orchestrator.GetTagURL), tag)

	respBytes, err := c.sendRequest(path, http.MethodGet, nil)
	if err != nil {
		return nil, err
	}

	tagMapping := &tagservicepb.TagMapping{}
	err = json.Unmarshal(respBytes, &tagMapping)
	if err != nil {
		return nil, err
	}

	return tagMapping, nil
}

// Resolve a tag down to all IP/URI members
func (c *Client) ResolveTag(tag string) ([]*tagservicepb.TagMapping, error) {
	path := fmt.Sprintf(orchestrator.GetFormatterString(orchestrator.ResolveTagURL), tag)

	respBytes, err := c.sendRequest(path, http.MethodPost, nil)
	if err != nil {
		return nil, err
	}

	tags := []*tagservicepb.TagMapping{}
	err = json.Unmarshal(respBytes, &tags)
	if err != nil {
		return nil, err
	}

	return tags, nil
}

// ListTags lists all tags and their mappings
func (c *Client) ListTags() ([]*tagservicepb.TagMapping, error) {
	path := orchestrator.GetFormatterString(orchestrator.ListTagURL)

	respBytes, err := c.sendRequest(path, http.MethodGet, nil)
	if err != nil {
		return nil, err
	}

	tags := []*tagservicepb.TagMapping{}
	err = json.Unmarshal(respBytes, &tags)
	if err != nil {
		return nil, err
	}

	return tags, nil
}

// Set a tag as a member of a group or as a mapping to a URI/IP
func (c *Client) SetTag(tag string, tagMapping *tagservicepb.TagMapping) error {
	path := fmt.Sprintf(orchestrator.GetFormatterString(orchestrator.SetTagURL), tag)

	reqBody, err := json.Marshal(tagMapping)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(path, http.MethodPost, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	return nil
}

// Delete an entire tag and all its member associations under it
func (c *Client) DeleteTag(tag string) error {
	path := fmt.Sprintf(orchestrator.GetFormatterString(orchestrator.DeleteTagURL), tag)

	_, err := c.sendRequest(path, http.MethodDelete, nil)
	if err != nil {
		return err
	}

	return nil
}

// Delete member from a tag
func (c *Client) DeleteTagMembers(tag string, member string) error {
	path := fmt.Sprintf(orchestrator.GetFormatterString(orchestrator.DeleteTagMemberURL), tag, member)

	_, err := c.sendRequest(path, http.MethodDelete, nil)
	if err != nil {
		return err
	}

	return nil
}

// List all configured namespaces
func (c *Client) ListNamespaces() (map[string][]config.CloudDeployment, error) {
	result, err := c.sendRequest(orchestrator.ListNamespacesURL, http.MethodGet, nil)
	if err != nil {
		return nil, err
	}

	namespaces := map[string][]config.CloudDeployment{}
	err = json.Unmarshal(result, &namespaces)
	if err != nil {
		return nil, err
	}

	return namespaces, nil
}
