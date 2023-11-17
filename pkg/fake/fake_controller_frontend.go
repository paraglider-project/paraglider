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

package fake

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/NetSys/invisinets/pkg/frontend"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
	"google.golang.org/protobuf/proto"
)

type FakeFrontendServer struct {
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

func GetFakePermitListRules() []*invisinetspb.PermitListRule {
	return []*invisinetspb.PermitListRule{
		{
			Id:        "id",
			Targets:   []string{"1.1.1.1", "2.2.2.2"},
			Direction: invisinetspb.Direction_INBOUND,
			SrcPort:   1,
			DstPort:   1,
			Protocol:  1,
			Tags:      []string{"tag1", "tag2"},
		},
	}
}

func GetFakeTagMapping(tagName string) []*tagservicepb.TagMapping {
	return []*tagservicepb.TagMapping{
		{
			TagName:   tagName,
			ChildTags: []string{"member1", "member2"},
		},
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

func (s *FakeFrontendServer) writeResponse(w http.ResponseWriter, resp any) error {
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

func (s *FakeFrontendServer) SetupFakeFrontendServer() string {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("unsupported request: %s %s", r.Method, path), http.StatusBadRequest)
			return
		}

		switch {
		// Create Resources
		case urlMatches(path, frontend.CreateResourceURL) && r.Method == http.MethodPost:
			resource := &invisinetspb.ResourceDescriptionString{}
			err := json.Unmarshal(body, resource)
			if err != nil {
				http.Error(w, fmt.Sprintf("error unmarshalling request body: %s", err), http.StatusBadRequest)
			}
			w.WriteHeader(http.StatusOK)
			return
		// Add/Delete Permit List Rules
		case urlMatches(path, frontend.AddPermitListRulesURL) && (r.Method == http.MethodPost || r.Method == http.MethodDelete):
			rules := []*invisinetspb.PermitListRule{}
			err := json.Unmarshal(body, &rules)
			if err != nil {
				http.Error(w, fmt.Sprintf("error unmarshalling request body: %s", err), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		// Get Permit List Rules
		case urlMatches(path, frontend.GetPermitListRulesURL) && r.Method == http.MethodGet:
			permitList := GetFakePermitListRules()
			err := s.writeResponse(w, permitList)
			if err != nil {
				http.Error(w, fmt.Sprintf("error writing response: %s", err), http.StatusInternalServerError)
				return
			}
			return
		// Tag Set/Get/Delete
		case urlMatches(path, frontend.GetTagURL):
			if r.Method == http.MethodPost {
				tags := []*tagservicepb.TagMapping{}
				err := s.writeResponse(w, tags)
				if err != nil {
					http.Error(w, fmt.Sprintf("error writing response: %s", err), http.StatusInternalServerError)
					return
				}
				return
			}
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Method == http.MethodGet {
				err := s.writeResponse(w, GetFakeTagMapping(getURLParams(path, string(frontend.GetTagURL))["tag"]))
				if err != nil {
					http.Error(w, fmt.Sprintf("error writing response: %s", err), http.StatusInternalServerError)
					return
				}
				return
			}
		// Delete Tag Mambers
		case urlMatches(path, frontend.DeleteTagMemberURL) && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
			return
		// Resolve Tag
		case urlMatches(path, frontend.ResolveTagURL) && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			err := s.writeResponse(w, GetFakeTagMappingLeafTags(getURLParams(path, string(frontend.ResolveTagURL))["tag"]))
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

func (s *FakeFrontendServer) TeardownServer() {
	s.server.Close()
}
