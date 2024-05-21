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
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
)

const (
	// url containing constantly updated endpoints of regions.
	endpointsURL = "https://control.cloud-object-storage.cloud.ibm.com/v2/endpoints"
)

// cache of regions, initialized by GetRegions(). Shouldn't be accessed directly outside of file.
var regionCache []string

// getRegions returns regionCache. if regionCache is empty, it's initialized.
func getRegions() ([]string, error) {
	if len(regionCache) != 0 {
		return regionCache, nil
	}
	response, err := http.Get(endpointsURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	err = json.Unmarshal([]byte(responseBody), &data)
	if err != nil {
		return nil, err
	}
	for regionName := range data["service-endpoints"].(map[string]interface{})["regional"].(map[string]interface{}) {
		regionCache = append(regionCache, regionName)
	}
	return regionCache, nil
}

// DoesSliceContain returns true if a slice contains an item
func DoesSliceContain[T comparable](slice []T, target T) bool {
	for _, val := range slice {
		if val == target {
			return true
		}
	}
	return false
}

// IsRegionValid returns true if region is a valid IBM region
func IsRegionValid(region string) (bool, error) {
	regions, err := getRegions()
	if err != nil {
		return false, err
	}
	return DoesSliceContain(regions[:], region), nil
}

// returns region of string with region validation
func ZoneToRegion(zone string) (string, error) {
	lastIndex := strings.LastIndex(zone, "-")
	if lastIndex == -1 {
		// Hyphen not found, handle this situation
		return "", fmt.Errorf("Wrong format for zone: missing hyphen.")
	}
	region := zone[:lastIndex]

	if ok, err := IsRegionValid(region); ok {
		return region, err
	} else {
		return "", err
	}
}

func GetZonesOfRegion(region string) []string {
	zonesPerRegion := 3
	res := make([]string, zonesPerRegion)
	for i := 0; i < zonesPerRegion; i++ {
		res[i] = region + "-" + fmt.Sprint(i+1)
	}
	return res
}

// AreStructsEqual returns true if two given structs of the same type have matching fields values
// on all types except those listed in fieldsToExclude
func AreStructsEqual(s1, s2 interface{}, fieldsToExclude []string) bool {
	v1 := reflect.ValueOf(s1)
	v2 := reflect.ValueOf(s2)

	if v1.Type() != v2.Type() {
		return false
	}

	for i := 0; i < v1.NumField(); i++ {
		fieldName := v1.Type().Field(i).Name
		if DoesSliceContain(fieldsToExclude, fieldName) {
			continue
		}

		if !reflect.DeepEqual(v1.Field(i).Interface(), v2.Field(i).Interface()) {
			return false
		}
	}
	return true
}

// returns hash value of any struct containing primitives,
// or slices of primitives.
// fieldsToExclude contains field names to be excluded
// from hash calculation.
func GetStructHash(s interface{}, fieldsToExclude []string) (uint64, error) {
	h := fnv.New64a()
	v := reflect.ValueOf(s)
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		fieldName := v.Type().Field(i).Name
		if DoesSliceContain(fieldsToExclude, fieldName) {
			// skip fields in fieldsToExclude from hash calculation
			continue
		}
		switch f.Kind() {
		case reflect.String:
			_, err := h.Write([]byte(f.String()))
			if err != nil {
				return 0, err
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			_, err := h.Write([]byte(fmt.Sprint(f.Int())))
			if err != nil {
				return 0, err
			}
		case reflect.Bool:
			_, err := h.Write([]byte(fmt.Sprint(f.Bool())))
			if err != nil {
				return 0, err
			}
		case reflect.Slice:
			for j := 0; j < f.Len(); j++ {
				_, err := h.Write([]byte(f.Index(j).String()))
				if err != nil {
					return 0, err
				}
			}
		}
	}
	return h.Sum64(), nil
}


// Gets subscription ID defined in environment variable
func GetIBMResourceGroupID() string {
	resourceGroupID := os.Getenv("PARAGLIDER_IBM_RESOURCE_GROUP_ID")
	if resourceGroupID == "" {
		panic("Environment variable 'PARAGLIDER_IBM_RESOURCE_GROUP_ID' is required for testing")
	}
	return resourceGroupID
}
