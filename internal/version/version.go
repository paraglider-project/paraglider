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

package version

import (
	"fmt"
)

// Values for these are injected by the build.
var (
	channel = "latest"
	release = "latest"
	version = "latest"
	commit  = "unknown"
)

// VersionInfo is used for a serializable representation of our versioning info.
type VersionInfo struct {
	Channel string `json:"channel"`
	Commit  string `json:"commit"`
	Release string `json:"release"`
	Version string `json:"version"`
}

// NewVersionInfo returns a new VersionInfo struct.
func NewVersionInfo() VersionInfo {
	return VersionInfo{
		Channel: Channel(),
		Commit:  Commit(),
		Release: Release(),
		Version: Version(),
	}
}

// Channel returns the designated channel for assets.
//
// For a real release this will be the major.minor - for any other build it's the same
// as Release().
func Channel() string {
	return channel
}

// Commit returns the full git SHA of the build.
//
// This should only be used for informational purposes.
func Commit() string {
	return commit
}

// Release returns the semver release version of the build.
//
// This should only be used for informational purposes.
func Release() string {
	return release
}

// Version returns the 'git describe' output of the build.
//
// This should only be used for informational purposes.
func Version() string {
	return version
}

// VersionString returns a formatted string representation of the version from a list of supported.
func VersionString(v VersionInfo) string {
	format := "Release: %s \nVersion: %s\n\nCommit: %s\n"
	return fmt.Sprintf(format, v.Release, v.Version, v.Commit)
}
