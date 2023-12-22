#! /bin/sh

# Redis (not using dev container features as there are problems with Apple Silicon and homebrew which ghcr.io/devcontainers-contrib/features/redis-homebrew:1 relies on)
# See the following links for more information
# - https://github.com/microsoft/vscode-dev-containers/issues/1492#issuecomment-1423265928
# - https://github.com/meaningful-ooo/devcontainer-features/issues/28
curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list
sudo apt-get update
sudo apt-get -y install redis

set -ex
go install gotest.tools/gotestsum@latest
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
