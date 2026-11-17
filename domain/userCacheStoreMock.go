package domain

import (
	"context"

	"uuid"

	"github.com/stretchr/testify/mock"
)

// UserCacheStoreMock — testify-мок для UserCacheStore.

type UserCacheStoreMock struct {
	mock.Mock
}

// compile-time проверка, что мок реализует интерфейс
var _ UserCacheStore = (*UserCacheStoreMock)(nil)

func NewUserCacheStoreMock(t interface {
	mock.TestingT
	Cleanup(func())
}) *UserCacheStoreMock {
	m := &UserCacheStoreMock{}
	m.Mock.Test(t)
	t.Cleanup(func() { m.AssertExpectations(t) })
	return m
}

func (m *UserCacheStoreMock) Set(ctx context.Context, user *User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *UserCacheStoreMock) Get(ctx context.Context, id uuid.UUID) (*User, error) {
	args := m.Called(ctx, id)
	if v := args.Get(0); v != nil {
		return v.(*User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UserCacheStoreMock) Update(ctx context.Context, id uuid.UUID, userOpt *UserOpt) error {
	args := m.Called(ctx, id, userOpt)
	return args.Error(0)
}

func (m *UserCacheStoreMock) Del(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}
