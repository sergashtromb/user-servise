package postgres

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"user_service/domain"
	"uuid"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
)

type UserStore struct {
	db *DataBase
}

func NewUserStore(db *DataBase) *UserStore {
	return &UserStore{
		db: db,
	}
}

func (us *UserStore) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {

	pool := us.db.GetPool()

	rows, err := pool.Query(ctx, `SELECT id, username, pass, email, phone, created_at, is_deleted 
					FROM users
					WHERE id = $1;`, &id)
	if err != nil {
		slog.Error("Failed get user by id", "err", err)
		return nil, err
	}
	defer rows.Close()

	var user domain.User
	if rows.Next() {
		rows.Scan(&user.Id, &user.UserName, &user.Password, &user.Email, &user.Phone, &user.CreatedAt, &user.IsDeleted)
	}

	return &user, nil
}
// TODO add custom error when fields empty
func (us *UserStore) Create(ctx context.Context, user *domain.User) error {

	pool := us.db.GetPool()

	_, err := pool.Exec(ctx, 
		`INSERT INTO users (username, pass, email, phone)
		VALUES ($1, $2, $3, $4);`, &user.UserName, &user.Password, &user.Email, &user.Phone)

	if err != nil {
		errUnicViolation := DbErrorFromUnicViolation(err)
		if errUnicViolation != nil {
			return errUnicViolation
		} else {
			return err
		}
	}

	return nil
}

func (us *UserStore) Update(ctx context.Context, id uuid.UUID, userOpt *domain.UserOpt) error {

	psql := squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)
	qr := psql.Update("users").Where(squirrel.Eq{"id": id.String(),})
	
	if userOpt.UserName.Define {
		if !userOpt.UserName.Valid {
			return NewDbError(ErrFieldCantBeEmpty, CodeDbErrFieldCantBeEmpty, []string{"username"})
		}

		qr = qr.Set("username", userOpt.UserName.Value)
	}

	if userOpt.Email.Define {
		if userOpt.Email.Valid {
			qr = qr.Set("email", userOpt.Email.Value)
		} else {
			qr = qr.Set("email", nil)
		}
	}

	if userOpt.Phone.Define {
		if userOpt.Phone.Valid {
			qr = qr.Set("phone", userOpt.Phone.Value)
		} else {
			qr = qr.Set("phone", nil)
		}
	}

	if userOpt.IsDeleted.Define {
		if !userOpt.IsDeleted.Valid {
			return NewDbError(ErrFieldCantBeEmpty, CodeDbErrFieldCantBeEmpty, []string{"is_deleted"})	
		} 

		qr = qr.Set("phone", userOpt.IsDeleted.Value)
	}

	query, args, err := qr.ToSql()
	if err != nil {
		return NewDbError(ErrConvertQuery, CodeDbErrConvertQuery, make([]string, 0))
	}

	pool := us.db.GetPool()

	_, err = pool.Exec(ctx, query, args...)
	if err != nil {
		errUnicViolation := DbErrorFromUnicViolation(err)
		if errUnicViolation != nil {
			return errUnicViolation
		} else {
			return err
		}
	}

	return nil
}

func (us *UserStore) Delete(ctx context.Context, id uuid.UUID) error {

	pool := us.db.GetPool()
	var exist bool
	err := pool.QueryRow(ctx, `
		UPDATE users 
		SET is_deleted = true 
		WHERE 
			id = $1 AND is_deleted = false 
		RETURNING true;`, id).Scan(&exist)

	if errors.Is(err, pgx.ErrNoRows) {
		return NewDbError(ErrUserDontExist, CodeDbErrUserDontExist, make([]string, 0))
	}
	
	if err != nil {
		return err
	}

	return nil
}
// TODO write universal get method with domain.UserOpt
func (us *UserStore) GetByEmail(ctx context.Context, email string) (*domain.User, error) {

	trEmail := strings.TrimSpace(email)
	pool := us.db.GetPool()

	var user domain.User
	err := pool.QueryRow(ctx, 
		`SELECT
			id, username, pass, email, phone, is_deleted, created_at
		FROM users
		WHERE
			email = $1 AND is_deleted = false`, &trEmail).Scan(
				&user.Id, &user.UserName, &user.Password, &user.Email, &user.Phone, &user.IsDeleted, &user.CreatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, NewDbError(ErrUserDontExist, CodeDbErrUserDontExist, make([]string, 0))
		} else {
			return nil, err
		}
	}

	return &user, nil
}

func (us *UserStore) GetByPhone(ctx context.Context, phone string) (*domain.User, error) {

	trPhone := strings.TrimSpace(phone)
	pool := us.db.GetPool()

	var user domain.User
	err := pool.QueryRow(ctx, 
		`SELECT
			id, username, pass, email, phone, is_deleted, created_at
		FROM users
		WHERE
			phone = $1 AND is_deleted = false`, &trPhone).Scan(
				&user.Id, &user.UserName, &user.Password, &user.Email, &user.Phone, &user.IsDeleted, &user.CreatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, NewDbError(ErrUserDontExist, CodeDbErrUserDontExist, make([]string, 0))
		} else {
			return nil, err
		}
	}

	return &user, nil
}