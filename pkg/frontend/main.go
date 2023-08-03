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
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"context"

	grpc "google.golang.org/grpc"
	insecure "google.golang.org/grpc/credentials/insecure"

	"encoding/json"

	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
)

const serveraddr = "localhost:50051"

func createErrorResponse(rid string, message string) gin.H {
	return gin.H{"id": rid, "err": message}
}

func permitListGet(c *gin.Context) {
	id := c.Param("id")
	emptyresourceId := invisinetspb.ResourceID{Id: id}

	conn, err := grpc.Dial(serveraddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return
	}

	client := invisinetspb.NewCloudPluginClient(conn)

	response, err := client.GetPermitList(context.Background(), &emptyresourceId)
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
		"id":              id,
		"permitlist":      response.AssociatedResource,
		"permitlist_json": string(pl_json[:]),
	})
}

func permitListRulesAdd(c *gin.Context) {
	id := c.Param("id")

	var permitListRules invisinetspb.PermitList

	if err := c.BindJSON(&permitListRules); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return
	}

	conn, err := grpc.Dial(serveraddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return
	}

	client := invisinetspb.NewCloudPluginClient(conn)

	response, err := client.AddPermitListRules(context.Background(), &permitListRules)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
	}

	defer conn.Close()

	c.JSON(http.StatusOK, gin.H{
		"id":       id,
		"response": response.Message,
	})
}

func permitListRulesDelete(c *gin.Context) {
	id := c.Param("id")

	var permitListRules invisinetspb.PermitList

	if err := c.BindJSON(&permitListRules); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return
	}

	conn, err := grpc.Dial(serveraddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return 
	}

	client := invisinetspb.NewCloudPluginClient(conn)

	response, err := client.DeletePermitListRules(context.Background(), &permitListRules)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
	}

	defer conn.Close()

	c.JSON(http.StatusOK, gin.H{
		"id":       id,
		"response": response.Message,
	})
}

func resourceCreate(c *gin.Context) {
	id := c.Param("id")

	var resource invisinetspb.ResourceDescription

	if err := c.BindJSON(&resource); err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return
	}

	conn, err := grpc.Dial(serveraddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
		return
	}

	client := invisinetspb.NewCloudPluginClient(conn)

	response, err := client.CreateResource(context.Background(), &resource)
	if err != nil {
		c.AbortWithStatusJSON(400, createErrorResponse(id, err.Error()))
	}

	defer conn.Close()

	c.JSON(http.StatusOK, gin.H{
		"id":       id,
		"response": response.Message,
	})
}


func main() {
	router := gin.Default()
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})

	router.GET("/resources/:id/permit-list", permitListGet)
	router.POST("/resources/:id/permit-list/rules", permitListRulesAdd)
	router.DELETE("/resources/:id/permit-list/rules", permitListRulesDelete)
	router.POST("/resources/:id/", resourceCreate)
  
	err := router.Run(":8080")
	if err != nil {
		fmt.Println(err.Error())
	}
}
