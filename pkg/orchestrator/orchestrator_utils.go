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

package orchestrator

// Private ASN ranges (RFC 6996)
const (
	MIN_PRIVATE_ASN_2BYTE uint32 = 64512
	MAX_PRIVATE_ASN_2BYTE uint32 = 65534
	MIN_PRIVATE_ASN_4BYTE uint32 = 4200000000
	MAX_PRIVATE_ASN_4BYTE uint32 = 4294967294
)
