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
	"os"

	"database/sql"
	"github.com/go-sql-driver/mysql"
	tagservicepb "github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
	
	"google.golang.org/grpc"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

type tagServiceServer struct {
	tagservicepb.UnimplementedTagServiceServer
	db *sql.DB
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
	// Store tag in local DB
	_, err := s.db.Exec("INSERT INTO tags (parent, child) VALUES (?, ?)", mapping.ParentTag.TagName, mapping.ChildTag.TagName)
    if err != nil {
        return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("SetTag: %v", err)
    }
    // id, err := result.LastInsertId()
    // if err != nil {
    //     return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("SetTag: %v", err)
    // }

    return  &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Created tag: %s", mapping.ParentTag.TagName)}, nil
}

func (s *tagServiceServer) GetTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.TagMapping, error){
	// Get tag from local DB
	var parentTag tagservicepb.Tag
	var childTag tagservicepb.Tag
	row := s.db.QueryRow("SELECT parent, child FROM tags WHERE parent = ?", tag.TagName)
	if err := row.Scan(&parentTag.TagName, &childTag.TagName); err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("GetTag %d: no such tag", tag.TagName)
        }
        return nil, fmt.Errorf("GetTag %d: %v", tag.TagName, err)
    }
    return &tagservicepb.TagMapping{ParentTag: &parentTag, ChildTag: &childTag}, nil
}

func (s *tagServiceServer) DeleteTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.BasicResponse, error){
	// Delete tag from local DB
	_, err := s.db.Exec("DELETE FROM tags WHERE parent = ?", tag.TagName)
    if err != nil {
        return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("DeleteTag: %v", err)
    }

	return  &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Deleted tag: %s", tag.TagName)}, nil
}

func newServer(database *sql.DB) *tagServiceServer {
	s := &tagServiceServer{db: database}
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
    db, err := sql.Open("mysql", cfg.FormatDSN())
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
	tagservicepb.RegisterTagServiceServer(grpcServer, newServer(db))
	err = grpcServer.Serve(lis)
	if err != nil {
		fmt.Println(err.Error())
	}
}


