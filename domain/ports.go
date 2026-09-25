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
	CheckForDuble(ctx context.Context, userOpt *UserOpt) (bool, error)
}