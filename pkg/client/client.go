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

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/NetSys/invisinets/pkg/frontend"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
)

type InvisinetsControllerClient interface {
	GetPermitList(cloud string, id string) (*invisinetspb.PermitList, error)
	AddPermitListRules(cloud string, permitList *invisinetspb.PermitList) error
	DeletePermitListRules(cloud string, permitList *invisinetspb.PermitList) error
	CreateResource(cloud string, resource *invisinetspb.ResourceDescriptionString) error
	GetTag(tag string) (*tagservicepb.TagMapping, error)
	ResolveTag(tag string) ([]*tagservicepb.TagMapping, error)
	SetTag(tag string, tagMapping *tagservicepb.TagMapping) error
	DeleteTag(tag string) error
	DeleteTagMembers(tag string, members []string) error
	GetNamespace() (string, error)
	SetNamespace(namespace string) error
}

type Client struct {
	InvisinetsControllerClient
	ControllerAddress string
}

// Proccess the response from the controller and return the body
func (c *Client) processResponse(resp *http.Response) ([]byte, error) {
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Request failed with status code %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return bodyBytes, nil
}

// Send a request to the controller and return the response body
func (c *Client) sendRequest(url string, method string, body io.Reader) ([]byte, error) {
	client := &http.Client{}

	url = fmt.Sprintf("http://%s%s", c.ControllerAddress, url)

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	bodyBytes, err := c.processResponse(resp)
	if err != nil {
		return nil, err
	}

	return bodyBytes, nil
}

// Get a permit list for a resource
func (c *Client) GetPermitList(cloud string, id string) (*invisinetspb.PermitList, error) {
	path := fmt.Sprintf(frontend.GetFormatterString(frontend.GetPermitListRulesURL), cloud, id)

	respBytes, err := c.sendRequest(path, http.MethodGet, nil)
	if err != nil {
		return nil, err
	}

	permitList := &invisinetspb.PermitList{}
	err = json.Unmarshal(respBytes, permitList)
	if err != nil {
		return nil, err
	}

	return permitList, nil
}

// Add permit list rules to a resource
func (c *Client) AddPermitListRules(cloud string, permitList *invisinetspb.PermitList) error {
	path := fmt.Sprintf(frontend.GetFormatterString(frontend.AddPermitListRulesURL), cloud)

	reqBody, err := json.Marshal(permitList)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(path, http.MethodPost, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	return nil
}

// Delete permit list rules from a resource
func (c *Client) DeletePermitListRules(cloud string, permitList *invisinetspb.PermitList) error {
	path := fmt.Sprintf(frontend.GetFormatterString(frontend.DeletePermitListRulesURL), cloud)

	reqBody, err := json.Marshal(permitList)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(path, http.MethodDelete, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	return nil
}

// Create a resource
func (c *Client) CreateResource(cloud string, resource *invisinetspb.ResourceDescriptionString) error {
	path := fmt.Sprintf(frontend.GetFormatterString(frontend.CreateResourceURL), cloud)

	reqBody, err := json.Marshal(resource)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(path, http.MethodPost, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	return nil
}

// Get the members of a tag
func (c *Client) GetTag(tag string) (*tagservicepb.TagMapping, error) {
	path := fmt.Sprintf(frontend.GetFormatterString(frontend.GetTagURL), tag)

	respBytes, err := c.sendRequest(path, http.MethodGet, nil)
	if err != nil {
		return nil, err
	}

	tagMapping := &tagservicepb.TagMapping{}
	err = json.Unmarshal(respBytes, tagMapping)
	if err != nil {
		return nil, err
	}

	return tagMapping, nil
}

// Resolve a tag down to all IP/URI members
func (c *Client) ResolveTag(tag string) ([]*tagservicepb.TagMapping, error) {
	path := fmt.Sprintf(frontend.GetFormatterString(frontend.ResolveTagURL), tag)

	respBytes, err := c.sendRequest(path, http.MethodGet, nil)
	if err != nil {
		return nil, err
	}

	tagMappings := []*tagservicepb.TagMapping{}
	err = json.Unmarshal(respBytes, &tagMappings)
	if err != nil {
		return nil, err
	}

	return tagMappings, nil
}

// Set a tag as a member of a group or as a mapping to a URI/IP
func (c *Client) SetTag(tag string, tagMapping *tagservicepb.TagMapping) error {
	path := fmt.Sprintf(frontend.GetFormatterString(frontend.SetTagURL), tag)

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
	path := fmt.Sprintf(frontend.GetFormatterString(frontend.DeleteTagURL), tag)

	_, err := c.sendRequest(path, http.MethodDelete, nil)
	if err != nil {
		return err
	}

	return nil
}

// Delete member(s) from a tag
func (c *Client) DeleteTagMembers(tag string, members []string) error {
	path := fmt.Sprintf(frontend.GetFormatterString(frontend.DeleteTagMembersURL), tag)

	reqBody, err := json.Marshal(members)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(path, http.MethodDelete, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	return nil
}

// Get the current namespace of the controller
func (c *Client) GetNamespace() (string, error) {
	path := frontend.GetFormatterString(frontend.GetNamespaceURL)

	respBytes, err := c.sendRequest(path, http.MethodGet, nil)
	if err != nil {
		return "", err
	}

	namespace := string(respBytes)

	return namespace, nil
}

// Set the namespace of the controller
func (c *Client) SetNamespace(namespace string) error {
	path := frontend.GetFormatterString(frontend.SetNamespaceURL)

	reqBody, err := json.Marshal(namespace)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(path, http.MethodPost, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	return nil
}
