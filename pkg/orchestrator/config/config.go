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

package config

type CloudDeployment struct {
	Name       string `yaml:"name"`
	Deployment string `yaml:"deployment"`
}

type CloudPlugin struct {
	Name string `yaml:"name"`
	Host string `yaml:"host"`
	Port string `yaml:"port"`
}

type Server struct {
	Port    string `yaml:"port"`
	Host    string `yaml:"host"`
	RpcPort string `yaml:"rpcPort"`
}

type TagService struct {
	Port string `yaml:"port"`
	Host string `yaml:"host"`
}

type Config struct {
	Server     Server     `yaml:"server"`
	TagService TagService `yaml:"tagService"`

	KVStore struct {
		Port string `yaml:"port"`
		Host string `yaml:"host"`
	} `yaml:"kvStore"`

	Namespaces   map[string][]CloudDeployment `yaml:"namespaces"`
	CloudPlugins []CloudPlugin                `yaml:"cloudPlugins"`
}
