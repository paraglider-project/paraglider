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

package rest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/paraglider-project/paraglider/pkg/orchestrator"
	"github.com/paraglider-project/paraglider/pkg/orchestrator/config"
	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
	"github.com/paraglider-project/paraglider/pkg/tag_service/tagservicepb"
	"google.golang.org/protobuf/proto"
)

const (
	CloudName = "fakecloud"
	Namespace = "fakenamespace"
)

type FakeOrchestratorRESTServer struct {
	server *httptest.Server
}

func urlMatches(url string, pattern string) bool {
	urlTokens := strings.Split(url, "/")
	patternTokens := strings.Split(pattern, "/")
	if len(urlTokens) != len(patternTokens) {
		return false
	}
	for i, token := range patternTokens {
		if urlTokens[i] != token && !strings.HasPrefix(token, ":") {
			return false
		}
		if strings.HasPrefix(token, ":") && strings.Contains(token, "cloud") && urlTokens[i] != CloudName {
			return false
		}
		if strings.HasPrefix(token, ":") && strings.Contains(token, "namespace") && urlTokens[i] != Namespace {
			return false
		}
	}
	return true
}

func getURLParams(url string, pattern string) map[string]string {
	params := map[string]string{}
	urlTokens := strings.Split(url, "/")
	patternTokens := strings.Split(pattern, "/")
	for i, token := range patternTokens {
		if strings.HasPrefix(token, ":") {
			params[strings.TrimPrefix(token, ":")] = urlTokens[i]
		}
		if strings.HasPrefix(token, "*") {
			params[strings.TrimPrefix(token, "*")] = strings.Join(urlTokens[i:], "/")
		}
	}
	return params
}

func GetFakePermitListRules() []*paragliderpb.PermitListRule {
	return []*paragliderpb.PermitListRule{
		{
			Name:      "name",
			Targets:   []string{"1.1.1.1", "2.2.2.2"},
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   1,
			DstPort:   1,
			Protocol:  1,
			Tags:      []string{"tag1", "tag2"},
		},
	}
}

func GetFakePermitListRuleNames() []string {
	return []string{"name1", "name2"}
}

func GetFakeTagMapping(tagName string) *tagservicepb.TagMapping {
	return &tagservicepb.TagMapping{
		Name:      tagName,
		ChildTags: []string{"member1", "member2"},
	}
}

func GetFakeTagMappingLeafTags(tagName string) []*tagservicepb.TagMapping {
	return []*tagservicepb.TagMapping{
		{
			Name: tagName,
			Uri:  proto.String("resource/uri"),
			Ip:   proto.String("3.3.3.3"),
		},
	}
}

func ListFakeTagMapping() []*tagservicepb.TagMapping {
	return []*tagservicepb.TagMapping{
		{
			Name:      "tag1",
			ChildTags: []string{"member1", "member2"},
		},
		{
			Name: "member1",
			Uri:  proto.String("resource/uri"),
			Ip:   proto.String("1.1.1.1"),
		},
		{
			Name: "member2",
			Uri:  proto.String("resource/uri"),
			Ip:   proto.String("2.2.2.2"),
		},
	}
}

func GetFakeNamespaces() map[string][]config.CloudDeployment {
	return map[string][]config.CloudDeployment{
		"namespace1": {
			{
				Name:       "cloud1",
				Deployment: "deployment1",
			},
		},
	}
}

func (s *FakeOrchestratorRESTServer) writeResponse(w http.ResponseWriter, resp any) error {
	bytes, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("error marshalling response object")
	}
	_, err = w.Write(bytes)
	if err != nil {
		return fmt.Errorf("error writing response")
	}
	return nil
}

func (s *FakeOrchestratorRESTServer) SetupFakeOrchestratorRESTServer() string {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("unsupported request: %s %s", r.Method, path), http.StatusBadRequest)
			return
		}

		switch {
		// List Namespaces
		case urlMatches(path, orchestrator.ListNamespacesURL) && r.Method == http.MethodGet:
			err := s.writeResponse(w, GetFakeNamespaces())
			if err != nil {
				http.Error(w, fmt.Sprintf("error writing response: %s", err), http.StatusInternalServerError)
				return
			}
			return
		// Create Resources (POST)
		case urlMatches(path, orchestrator.CreateOrAttachResourcePOSTURL) && r.Method == http.MethodPost:
			resource := &paragliderpb.ResourceDescriptionString{}
			err := json.Unmarshal(body, resource)
			if err != nil {
				http.Error(w, fmt.Sprintf("error unmarshalling request body: %s", err), http.StatusBadRequest)
			}
			err = s.writeResponse(w, map[string]string{"name": resource.Name})
			if err != nil {
				http.Error(w, fmt.Sprintf("error writing response: %s", err), http.StatusInternalServerError)
			}
			return
		// Create Resources (PUT)
		case urlMatches(path, orchestrator.CreateResourcePUTURL) && r.Method == http.MethodPut:
			resource := &paragliderpb.ResourceDescriptionString{}
			err := json.Unmarshal(body, resource)
			if err != nil {
				http.Error(w, fmt.Sprintf("error unmarshalling request body: %s", err), http.StatusBadRequest)
			}
			err = s.writeResponse(w, map[string]string{"name": strings.Split(path, "/")[len(strings.Split(path, "/"))-1]})
			if err != nil {
				http.Error(w, fmt.Sprintf("error writing response: %s", err), http.StatusInternalServerError)
			}
			return
		// Add Permit List Rules
		case urlMatches(path, orchestrator.AddPermitListRulesURL) && (r.Method == http.MethodPost):
			rules := []*paragliderpb.PermitListRule{}
			err := json.Unmarshal(body, &rules)
			if err != nil {
				http.Error(w, fmt.Sprintf("error unmarshalling request body: %s", err), http.StatusBadRequest)
				return
			}
			return
		// Delete Permit List Rules
		case urlMatches(path, orchestrator.DeletePermitListRulesURL) && (r.Method == http.MethodPost):
			rules := []string{}
			err := json.Unmarshal(body, &rules)
			if err != nil {
				http.Error(w, fmt.Sprintf("error unmarshalling request body: %s", err), http.StatusBadRequest)
				return
			}
			return
		// Individual Rule Add (POST)
		case urlMatches(path, orchestrator.PermitListRulePOSTURL) && (r.Method == http.MethodPost):
			rule := &paragliderpb.PermitListRule{}
			err := json.Unmarshal(body, rule)
			if err != nil {
				http.Error(w, fmt.Sprintf("error unmarshalling request body: %s", err), http.StatusBadRequest)
				return
			}
			return
		// Individual Rule Add (PUT)
		case urlMatches(path, orchestrator.PermitListRulePUTURL) && (r.Method == http.MethodPut):
			rule := &paragliderpb.PermitListRule{}
			err := json.Unmarshal(body, rule)
			if err != nil {
				http.Error(w, fmt.Sprintf("error unmarshalling request body: %s", err), http.StatusBadRequest)
				return
			}
			return
		// Individual Rule Delete
		case urlMatches(path, orchestrator.PermitListRulePUTURL) && (r.Method == http.MethodDelete):
			w.WriteHeader(http.StatusOK)
			return
		// Get Permit List Rules
		case urlMatches(path, orchestrator.GetPermitListRulesURL) && r.Method == http.MethodGet:
			permitList := GetFakePermitListRules()
			err := s.writeResponse(w, permitList)
			if err != nil {
				http.Error(w, fmt.Sprintf("error writing response: %s", err), http.StatusInternalServerError)
				return
			}
			return
		// Tag List
		case urlMatches(path, orchestrator.ListTagURL):
			if r.Method == http.MethodGet {
				err := s.writeResponse(w, ListFakeTagMapping())
				if err != nil {
					http.Error(w, fmt.Sprintf("error writing response: %s", err), http.StatusInternalServerError)
					return
				}
				return
			}
		// Tag Get/Delete
		case urlMatches(path, orchestrator.GetTagURL):
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Method == http.MethodGet {
				err := s.writeResponse(w, GetFakeTagMapping(getURLParams(path, string(orchestrator.GetTagURL))["tag"]))
				if err != nil {
					http.Error(w, fmt.Sprintf("error writing response: %s", err), http.StatusInternalServerError)
					return
				}
				return
			}
		// Tag Set
		case urlMatches(path, orchestrator.SetTagURL):
			if r.Method == http.MethodPost {
				tags := []*tagservicepb.TagMapping{}
				err := s.writeResponse(w, tags)
				if err != nil {
					http.Error(w, fmt.Sprintf("error writing response: %s", err), http.StatusInternalServerError)
					return
				}
				return
			}
		// Delete Tag Mambers
		case urlMatches(path, orchestrator.DeleteTagMemberURL) && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
			return
		// Resolve Tag
		case urlMatches(path, orchestrator.ResolveTagURL) && r.Method == http.MethodPost:
			mappings := GetFakeTagMappingLeafTags(getURLParams(path, string(orchestrator.ResolveTagURL))["tag"])
			err := s.writeResponse(w, &mappings)
			if err != nil {
				http.Error(w, fmt.Sprintf("error writing response: %s", err), http.StatusInternalServerError)
				return
			}

			return
		}
		fmt.Printf("unsupported request: %s %s\n", r.Method, path)
		http.Error(w, fmt.Sprintf("unsupported request: %s %s", r.Method, path), http.StatusBadRequest)
	})

	server := httptest.NewServer(handler)
	return server.URL
}

func (s *FakeOrchestratorRESTServer) TeardownServer() {
	s.server.Close()
}
