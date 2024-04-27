//go:build unit

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

package kvstore

import (
	"context"
	"testing"

	"github.com/go-redis/redismock/v9"
	storepb "github.com/paraglider-project/paraglider/pkg/kvstore/storepb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSet(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := NewKVStoreServer(db)

	key := "test"
	value := "value"
	cloud := "cloud"
	namespace := "namespace"

	mock.ExpectSet(getFullKey(key, cloud, namespace), value, 0).SetVal("OK")
	resp, err := server.Set(context.Background(), &storepb.SetRequest{Key: key, Value: value, Cloud: cloud, Namespace: namespace})

	require.Nil(t, err)
	require.NotNil(t, resp)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestGet(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := NewKVStoreServer(db)

	key := "test"
	value := "value"
	cloud := "cloud"
	namespace := "namespace"

	mock.ExpectGet(getFullKey(key, cloud, namespace)).SetVal(value)
	resp, err := server.Get(context.Background(), &storepb.GetRequest{Key: key, Cloud: cloud, Namespace: namespace})

	require.Nil(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, value, resp.Value)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestDelete(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := NewKVStoreServer(db)

	key := "test"
	cloud := "cloud"
	namespace := "namespace"

	mock.ExpectDel(getFullKey(key, cloud, namespace)).SetVal(0)
	resp, err := server.Delete(context.Background(), &storepb.DeleteRequest{Key: key, Cloud: cloud, Namespace: namespace})

	require.Nil(t, err)
	require.NotNil(t, resp)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}
