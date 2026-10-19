package domain

import (
	"context"

	"uuid"

	"github.com/stretchr/testify/mock"
)

// UserStoreMock — testify-мок для dm.UserStore.
// Поменяйте import dm и типы User/UserOpt на ваши, если интерфейс в другом пакете.
type UserStoreMock struct {
	mock.Mock
}

// compile-time проверка, что мок реализует интерфейс
var _ UserStore = (*UserStoreMock)(nil)

func NewUserStoreMock(t interface {
	mock.TestingT
	Cleanup(func())
}) *UserStoreMock {
	m := &UserStoreMock{}
	m.Mock.Test(t)
	t.Cleanup(func() { m.AssertExpectations(t) })
	return m
}

func (m *UserStoreMock) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	args := m.Called(ctx, id)
	if v := args.Get(0); v != nil {
		return v.(*User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UserStoreMock) Update(ctx context.Context, id uuid.UUID, userOpt *UserOpt) error {
	args := m.Called(ctx, id, userOpt)
	return args.Error(0)
}

func (m *UserStoreMock) Create(ctx context.Context, user *User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *UserStoreMock) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *UserStoreMock) GetByEmail(ctx context.Context, email string) (*User, error) {
	args := m.Called(ctx, email)
	if v := args.Get(0); v != nil {
		return v.(*User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UserStoreMock) GetByPhone(ctx context.Context, phone string) (*User, error) {
	args := m.Called(ctx, phone)
	if v := args.Get(0); v != nil {
		return v.(*User), args.Error(1)
	}
	return nil, args.Error(1)
}
