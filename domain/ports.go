package domain

import (
	"context"
	"uuid"
)

type UserStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	Update(ctx context.Context, id uuid.UUID, userOpt *UserOpt) error
	Create(ctx context.Context, user *User) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByPhone(ctx context.Context, phone string) (*User, error)
}

type SessionStore interface {
	Registration(ctx context.Context, session *Session, familyId uuid.UUID) error
	GetAllSession(ctx context.Context, userId uuid.UUID) ([]Session, error)
	GetSessionByFamilyId(ctx context.Context, userId, familyId uuid.UUID) (*Session, error)
	DeleteAll(ctx context.Context, id uuid.UUID) error
	DeleteByRefresh(ctx context.Context, id uuid.UUID, refresh string) error
	CreateGracePeriodic(ctx context.Context, userId, familyId uuid.UUID, gracePeriodic *GracePeriodic) error
	GetFromGracePeriodic(ctx context.Context, userId, familyId uuid.UUID, version string) (string, string, error)
	UpdateIpAdress(ctx context.Context, userId, familyId uuid.UUID, ip string) error
}
