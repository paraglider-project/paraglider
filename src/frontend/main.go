package main

import (
  "net/http"

  "github.com/gin-gonic/gin"

  grpc "google.golang.org/grpc"
  "context"

//   "encoding/json"
//   "fmt"
//   "io"

  "github.com/NetSys/invisinets/src/proto/invisinetspb"
)


func main() {
  router := gin.Default()
  router.GET("/ping", func(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{
      "message": "pong",
    })
  })

  router.GET("/permit-lists/:id", permitListGet)
  router.POST("/permit-lists/:id", permitListPost)
//   router.DELETE("/permit-lists/:id", permitListDelete)

  router.Run(":8080") // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}

func permitListGet(c *gin.Context) {
	id := c.Param("id")
	// TODO: Create a connection with the gRPC server and get the correct permit list
	c.JSON(http.StatusOK, gin.H{
		"id": id,
	})
}

func permitListPost(c *gin.Context) {
	id := c.Param("id")

	var permitList invisinetspb.PermitList
	err := c.BindJSON(&permitList)

	var message string
	if err != nil {
		message = err.Error()
		c.AbortWithStatusJSON(400, gin.H{"id": id, "err": message})
		return // TODO: Make this more verbose
	}

	conn, err := grpc.Dial("localhost:50051")
	if err != nil {
		message = err.Error()
		c.AbortWithStatusJSON(400, gin.H{"id": id, "err": message})
	}

	client := invisinetspb.NewCloudPluginClient(conn)
	response, err := client.SetPermitList(context.Background(), &permitList)
	if err != nil {
		message = err.Error()
		c.AbortWithStatusJSON(400, gin.H{"id": id, "err": message})
	}

	defer conn.Close()
	
	c.JSON(http.StatusOK, gin.H{
		"id": id,
		"err": message,
		"response": response.Message,
	})
}