package azure

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/stretchr/testify/assert"
)

func TestGetPriority(t *testing.T) {
	var reservedPriorities = make(map[int32]*armnetwork.SecurityRule)
	var start int32 = minPriority
	var end int32 = maxPriority
	var ascendingSearch bool = true
	var priority int32

	t.Run("TestGetPriorityAscending", func(t *testing.T) {
		priority = getPriority(reservedPriorities, start, end, ascendingSearch)
		assert.Equal(t, priority, int32(minPriority))
	})

	t.Run("TestGetPriorityDescending", func(t *testing.T) {
		priority = getPriority(reservedPriorities, start, end, !ascendingSearch)
		assert.Equal(t, priority, int32(maxPriority))
	})
}
