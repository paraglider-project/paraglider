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

package main


import (
	"context"
	"fmt"

	grpc "google.golang.org/grpc"
	insecure "google.golang.org/grpc/credentials/insecure"
	tagservicepb "github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
)

func add_tag(client tagservicepb.TagServiceClient) {
	tagMap := tagservicepb.TagMapping{ParentTag: &tagservicepb.Tag{TagName: "testparent3"}, ChildTag: &tagservicepb.Tag{TagName: "testchild"}}

	response, err := client.SetTag(context.Background(), &tagMap)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(response.Message)
}

func get_tag(client tagservicepb.TagServiceClient) {
	tag := tagservicepb.Tag{TagName: "testparent3"}
	response, err := client.GetTag(context.Background(), &tag)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("%s -> %s", response.ParentTag.TagName, response.ChildTag.TagName)
}

func delete_tag(client tagservicepb.TagServiceClient) {
	tag := tagservicepb.Tag{TagName: "testparent3"}
	response, err := client.DeleteTag(context.Background(), &tag)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(response.Message)
}

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer conn.Close()

	client := tagservicepb.NewTagServiceClient(conn)

	add_tag(client)
	get_tag(client)
	delete_tag(client)
	add_tag(client)
	add_tag(client)
}