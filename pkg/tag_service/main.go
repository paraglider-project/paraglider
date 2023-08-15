// package main

// import (
//     "database/sql"
//     "fmt"
//     "log"
//     "os"

//     "github.com/go-sql-driver/mysql"
// 	tagservicepb "github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
// )

// func newServer(database *sql.DB) *cloudPluginServer {
// 	s := &cloudPluginServer{db: database}
// 	return s
// }

// var (
// 	port = flag.Int("port", 50051, "The server port")
// 	db *sql.DB
// )

// func main() {
//     // Capture connection properties.
//     cfg := mysql.Config{
//         User:   os.Getenv("DBUSER"),
//         Passwd: os.Getenv("DBPASS"),
//         Net:    "tcp",
//         Addr:   "127.0.0.1:3306",
//         DBName: "tags",
//     }
//     // Get a database handle.
//     var err error
//     db, err = sql.Open("mysql", cfg.FormatDSN())
//     if err != nil {
//         log.Fatal(err)
//     }

//     pingErr := db.Ping()
//     if pingErr != nil {
//         log.Fatal(pingErr)
//     }
//     fmt.Println("Connected!")

// 	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
// 	if err != nil {
// 		log.Fatalf("failed to listen: %v", err)
// 	}
// 	var opts []grpc.ServerOption
// 	grpcServer := grpc.NewServer(opts...)
// 	invisinetspb.RegisterCloudPluginServer(grpcServer, newServer(&db))
// 	err = grpcServer.Serve(lis)
// 	if err != nil {
// 		fmt.Println(err.Error())
// 	}
// }