package main

import (
  "net/http"

  "github.com/gin-gonic/gin"
)

func main() {
  router := gin.Default()
  router.GET("/ping", func(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{
      "message": "pong",
    })
  })

  router.GET("/permit-lists/:id", permitListGet)
//   router.POST("/permit-lists/:id", permitListPost)
//   router.DELETE("/permit-lists/:id", permitListDelete)

  router.Run(":8080") // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}

func permitListGet(c *gin.Context) {
	id := c.Param("id")
	// Create a connection with the gRPC server and get the correct permit list
	c.JSON(http.StatusOK, gin.H{
		"id": id,
	})
}
// TODO: HTTP server to accept the requests shown in the spec document and make the appropriate plugin gRPC calls




// Step 1: GET/POST for permit lists 