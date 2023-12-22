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

package rest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/NetSys/invisinets/pkg/orchestrator"
	"github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
	"google.golang.org/protobuf/proto"
)

const (
	CloudName = "example-cloud"
	Namespace = "example-namespace"
)

type FakeOrchestratorRESTServer struct {
	server *httptest.Server
}

func urlMatches(url string, pattern string) bool {
	urlTokens := strings.Split(url, "/")
	patternTokens := strings.Split(pattern, "/")
	for i, token := range patternTokens {
		if urlTokens[i] != token && !strings.HasPrefix(token, ":") && !strings.HasPrefix(token, "*") {
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

func GetFakePermitList(resourceUri string) *invisinetspb.PermitList {
	return &invisinetspb.PermitList{
		AssociatedResource: resourceUri,
		Rules: []*invisinetspb.PermitListRule{
			{
				Id:        "id",
				Targets:   []string{"1.1.1.1", "2.2.2.2"},
				Direction: invisinetspb.Direction_INBOUND,
				SrcPort:   1,
				DstPort:   1,
				Protocol:  1,
				Tags:      []string{"tag1", "tag2"},
			},
		},
	}
}

func GetFakeTagMapping(tagName string) *tagservicepb.TagMapping {
	return &tagservicepb.TagMapping{
		TagName:   tagName,
		ChildTags: []string{"member1", "member2"},
	}
}

func GetFakeTagMappingLeafTags(tagName string) []*tagservicepb.TagMapping {
	return []*tagservicepb.TagMapping{
		{
			TagName: tagName,
			Uri:     proto.String("resource/uri"),
			Ip:      proto.String("3.3.3.3"),
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
		// Create Resources
		case urlMatches(path, orchestrator.CreateResourceURL) && r.Method == http.MethodPost:
			resource := &invisinetspb.ResourceDescriptionString{}
			err := json.Unmarshal(body, resource)
			if err != nil {
				http.Error(w, fmt.Sprintf("error unmarshalling request body: %s", err), http.StatusBadRequest)
			}
			w.WriteHeader(http.StatusOK)
			err = s.writeResponse(w, map[string]string{"uri": resource.Id})
			if err != nil {
				http.Error(w, fmt.Sprintf("error writing response: %s", err), http.StatusInternalServerError)
			}
			return
		// Add/Delete Permit List Rules
		case urlMatches(path, orchestrator.AddPermitListRulesURL) && (r.Method == http.MethodPost || r.Method == http.MethodDelete):
			permitList := &invisinetspb.PermitList{}
			err := json.Unmarshal(body, permitList)
			if err != nil {
				http.Error(w, fmt.Sprintf("error unmarshalling request body: %s", err), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		// Get Permit List Rules
		case urlMatches(path, orchestrator.GetPermitListRulesURL) && r.Method == http.MethodGet:
			permitList := GetFakePermitList(getURLParams(path, string(orchestrator.GetPermitListRulesURL))["id"])
			err := s.writeResponse(w, permitList)
			if err != nil {
				http.Error(w, fmt.Sprintf("error writing response: %s", err), http.StatusInternalServerError)
				return
			}
			return
		// Tag Set/Get/Delete
		case urlMatches(path, orchestrator.GetTagURL):
			if r.Method == http.MethodPost || r.Method == http.MethodDelete {
				tags := []*tagservicepb.TagMapping{}
				err := s.writeResponse(w, tags)
				if err != nil {
					http.Error(w, fmt.Sprintf("error writing response: %s", err), http.StatusInternalServerError)
					return
				}
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
		// Delete Tag Mambers
		case urlMatches(path, orchestrator.DeleteTagMembersURL) && r.Method == http.MethodDelete:
			tags := []*tagservicepb.TagMapping{}
			err := s.writeResponse(w, tags)
			if err != nil {
				http.Error(w, fmt.Sprintf("error writing response: %s", err), http.StatusInternalServerError)
				return
			}
			return
		// Resolve Tag
		case urlMatches(path, orchestrator.ResolveTagURL) && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			err := s.writeResponse(w, GetFakeTagMappingLeafTags(getURLParams(path, string(orchestrator.ResolveTagURL))["tag"]))
			if err != nil {
				http.Error(w, fmt.Sprintf("error writing response: %s", err), http.StatusInternalServerError)
				return
			}
			return
		// Namespace Get
		case urlMatches(path, orchestrator.GetNamespaceURL) && r.Method == http.MethodGet:
			err := s.writeResponse(w, map[string]string{"namespace": Namespace})
			if err != nil {
				http.Error(w, fmt.Sprintf("error writing response: %s", err), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		// Namespace Set
		case urlMatches(path, orchestrator.SetNamespaceURL) && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusOK)
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
