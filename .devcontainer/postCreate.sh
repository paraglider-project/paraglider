#! /bin/sh

set -ex
go install gotest.tools/gotestsum@latest
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
