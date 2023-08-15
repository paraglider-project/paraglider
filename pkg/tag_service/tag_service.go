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

	"database/sql"
	tagservicepb "github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
	
	"google.golang.org/grpc"
)

var (
	port = flag.Int("port", 50051, "The server port")
	db *sql.DB
)

type tagServiceServer struct {
	tagservicepb.UnimplementedTagServiceServer
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

func (s *tagServiceServer) SetTag(c context.Context, mapping *TagMapping) (*BasicResponse, error){
	// Store tag in local DB or in its respective cloud
	rows, err := db.Query("SELECT * FROM tags WHERE artist = ?", mapping.)
}

func (s *tagServiceServer) GetTag(context.Context, *Tag) (*BasicResponse, error){
	// Get tag from local DB or in its respective cloud
}

func (s *tagServiceServer) DeleteTag(context.Context, *Tag) (*BasicResponse, error){
	// Delete tag from local DB or in its respective cloud
}

func newServer(database *sql.DB) *cloudPluginServer {
	s := &cloudPluginServer{db: database}
	return s
}

func main() {
    // Capture connection properties.
    cfg := mysql.Config{
        User:   os.Getenv("DBUSER"),
        Passwd: os.Getenv("DBPASS"),
        Net:    "tcp",
        Addr:   "127.0.0.1:3306",
        DBName: "tags",
    }
    // Get a database handle.
    var err error
    db, err = sql.Open("mysql", cfg.FormatDSN())
    if err != nil {
        log.Fatal(err)
    }

    pingErr := db.Ping()
    if pingErr != nil {
        log.Fatal(pingErr)
    }
    fmt.Println("Connected!")

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	invisinetspb.RegisterCloudPluginServer(grpcServer, newServer(&db))
	err = grpcServer.Serve(lis)
	if err != nil {
		fmt.Println(err.Error())
	}
}


