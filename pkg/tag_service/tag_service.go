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
	"flag"
	"fmt"
	"log"
	"net"
	// "os"

	// "database/sql"
	// "github.com/go-sql-driver/mysql"
	"github.com/redis/go-redis/v9"
	tagservicepb "github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
	
	"google.golang.org/grpc"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

type tagServiceServer struct {
	tagservicepb.UnimplementedTagServiceServer
	client *redis.Client
}

// func albumsByArtist(name string) ([]Album, error) {
//     // An albums slice to hold data from returned rows.
//     var albums []Album

//     rows, err := db.Query("SELECT * FROM album WHERE artist = ?", name)
//     if err != nil {
//         return nil, fmt.Errorf("albumsByArtist %q: %v", name, err)
//     }
//     defer rows.Close()
//     // Loop through rows, using Scan to assign column data to struct fields.
//     for rows.Next() {
//         var alb Album
//         if err := rows.Scan(&alb.ID, &alb.Title, &alb.Artist, &alb.Price); err != nil {
//             return nil, fmt.Errorf("albumsByArtist %q: %v", name, err)
//         }
//         albums = append(albums, alb)
//     }
//     if err := rows.Err(); err != nil {
//         return nil, fmt.Errorf("albumsByArtist %q: %v", name, err)
//     }
//     return albums, nil
// }

func (s *tagServiceServer) SetTag(c context.Context, mapping *tagservicepb.TagMapping) (*tagservicepb.BasicResponse, error){
	err := s.client.SAdd(c, mapping.ParentTag, mapping.ChildTags).Err()
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("SetTag: %v", err)
	}

    return  &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Created/updated tag: %s", mapping.ParentTag)}, nil
}

func (s *tagServiceServer) GetTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.TagMapping, error){
	childrenTags, err := s.client.SMembers(c, tag.TagName).Result()
	if err != nil {
		return nil, fmt.Errorf("GetTag %d: %v", tag.TagName, err)
	}
    return &tagservicepb.TagMapping{ParentTag: tag.TagName, ChildTags: childrenTags}, nil
}

func (s *tagServiceServer) DeleteTagMember(c context.Context, mapping *tagservicepb.TagMapping) (*tagservicepb.BasicResponse, error){
	err := s.client.SRem(c, mapping.ParentTag, mapping.ChildTags).Err()
	if err != nil {
		return nil, fmt.Errorf("DeleteTagMember %d: %v", mapping.ParentTag, err)
	}
    return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Deleted members from tag: %s", mapping.ParentTag)}, nil
}

func (s *tagServiceServer) DeleteTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.BasicResponse, error){
	childrenTags, err := s.client.SMembers(c, tag.TagName).Result()
	if err != nil {
		return nil, fmt.Errorf("DeleteTag %d: %v", tag.TagName, err)
	}

	err = s.client.SRem(c, tag.TagName, childrenTags).Err()
	if err != nil {
		return nil, fmt.Errorf("DeleteTag %d: %v", tag.TagName, err)
	}
    return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Deleted tag: %s", tag.TagName)}, nil
}

func newServer(database *redis.Client) *tagServiceServer {
	s := &tagServiceServer{client: database}
	return s
}

func main() {
    // Capture connection properties.
    // cfg := mysql.Config{
    //     User:   os.Getenv("DBUSER"),
    //     Passwd: os.Getenv("DBPASS"),
    //     Net:    "tcp",
    //     Addr:   "127.0.0.1:3306",
    //     DBName: "tags",
    // }

    // // Get a database handle.
    // var err error
    // db, err := sql.Open("mysql", cfg.FormatDSN())
    // if err != nil {
    //     log.Fatal(err)
    // }

    // pingErr := db.Ping()
    // if pingErr != nil {
    //     log.Fatal(pingErr)
    // }
    // fmt.Println("Connected!")

	client := redis.NewClient(&redis.Options{
        Addr:	  "localhost:6379",
        Password: "", // no password set
        DB:		  0,  // use default DB
    })

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	tagservicepb.RegisterTagServiceServer(grpcServer, newServer(client))
	err = grpcServer.Serve(lis)
	if err != nil {
		fmt.Println(err.Error())
	}
}


