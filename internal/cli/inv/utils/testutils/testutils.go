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

package testutils

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/NetSys/invisinets/internal/cli/inv/settings"
)

const (
	CloudName = "example-cloud"
)

type FakeFrontendServer struct {
	server            *httptest.Server
	lastRequestBody   []byte
	lastRequestMethod string
}

func (s *FakeFrontendServer) GetLastRequestMethod() string {
	return s.lastRequestMethod
}

func (s *FakeFrontendServer) GetLastRequestBody() []byte {
	return s.lastRequestBody
}

func (s *FakeFrontendServer) SetupFakeServer() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("unsupported request: %s %s", r.Method, path), http.StatusBadRequest)
			return
		}
		s.lastRequestMethod = r.Method
		s.lastRequestBody = body

		switch {
		case strings.Contains(path, fmt.Sprintf("cloud/%s/resources/", CloudName)):
			w.WriteHeader(http.StatusOK)
			return
		case strings.Contains(path, fmt.Sprintf("cloud/%s/permit-list/rules", CloudName)):
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusOK)
			}
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusOK)
			}
			return
		case strings.Contains(path, fmt.Sprintf("cloud/%s/permit-list/uri", CloudName)):
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK) // TODO @smcclure20: should we include a body?
			}
			return
		case strings.Contains(path, "tags/"):
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusOK)
			}
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
			}
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusOK)
			}
			return
		case strings.Contains(path, "namespace/"):
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
			}
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusOK)
			}
			return
		}
		fmt.Printf("unsupported request: %s %s\n", r.Method, path)
		http.Error(w, fmt.Sprintf("unsupported request: %s %s", r.Method, path), http.StatusBadRequest)
	})

	server := httptest.NewServer(handler)
	settings.ServerAddr = server.URL
}

func (s *FakeFrontendServer) TeardownServer() {
	s.server.Close()
}
