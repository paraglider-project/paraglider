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

package frontend

import (
  "net/http"
  "fmt"

  "github.com/gin-gonic/gin"

  grpc "google.golang.org/grpc"
  insecure "google.golang.org/grpc/credentials/insecure"
  "context"

  "encoding/json"

  invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
)

func createErrorResponse(rid string, message string) gin.H {
	return gin.H{"id": rid, "err": message}
}

func permitListGet(c *gin.Context) {
	id := c.Param("id")
	emptyresource := invisinetspb.Resource{Id: id}

	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return
	}

	client := invisinetspb.NewCloudPluginClient(conn)
	response, err := client.GetPermitList(context.Background(), &emptyresource)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
	}

	defer conn.Close()
	
	pl_json, err := json.Marshal(response)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id": id,
		"permitlist": response.Id,
		"permitlist_json": string(pl_json[:]),
	})
}


func main() {
	router := gin.Default()
	router.GET("/ping", func(c *gin.Context) {
	  c.JSON(http.StatusOK, gin.H{
		"message": "pong",
	  })
	})
  
	router.GET("/permit-lists/:id", permitListGet)
  
	err := router.Run(":8080")
	if err != nil {
		fmt.Println(err.Error())
	}
  }