package domain

import (
	"context"
	"uuid"

	"github.com/stretchr/testify/mock"
)

type SessionStoreMock struct {
	mock.Mock
}

var _ SessionStore = (*SessionStoreMock)(nil)

func NewSessionStoreMock(t interface {
	mock.TestingT
	Cleanup(func())
}) *SessionStoreMock {
	m := &SessionStoreMock{}
	m.Mock.Test(t)
	t.Cleanup(func() { m.AssertExpectations(t) })
	return m
}

func (m *SessionStoreMock) Registration(ctx context.Context, session *Session, familyId uuid.UUID) error {
	args := m.Called(ctx, session, familyId)
	return args.Error(0)
}

func (m *SessionStoreMock) GetAllSession(ctx context.Context, userId uuid.UUID) ([]Session, error) {
	args := m.Called(ctx, userId)
	if v := args.Get(0); v != nil {
		return v.([]Session), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *SessionStoreMock) GetSessionByFamilyId(ctx context.Context, userId uuid.UUID, familyId uuid.UUID) (*Session, error) {
	args := m.Called(ctx, userId, familyId)
	if v := args.Get(0); v != nil {
		return v.(*Session), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *SessionStoreMock) UpdateRefreshToken(ctx context.Context, id uuid.UUID, oldToken string, newToken string) error {
	args := m.Called(ctx, id, oldToken, newToken)
	return args.Error(0)
}

func (m *SessionStoreMock) DeleteAll(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *SessionStoreMock) DeleteByRefresh(ctx context.Context, id uuid.UUID, refresh string) error {
	args := m.Called(ctx, id, refresh)
	return args.Error(0)
}
