package postgres

import (
	"context"
	"errors"
	"log/slog"
	"user_service/domain"
	"uuid"

	"github.com/jackc/pgx/v5/pgconn"
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
		var pgErr *pgconn.PgError

		if errors.As(err, &pgErr) && pgErr.Code == CodeErrUniqueViolation {

			dbErr := NewDbError(ErrUserAlreadyExists, CodeDbErrUserAlreadyExists, make([]string, 0))

			switch pgErr.ConstraintName {
			case "users_username_idx":
				dbErr.Fields = append(dbErr.Fields, "username")
			case "users_email_idx":
				dbErr.Fields = append(dbErr.Fields, "email")
			case "users_phone_idx":
				dbErr.Fields = append(dbErr.Fields, "email")
			}

			return dbErr
		} else {
			return err
		}
	}

	return nil
}

func (us *UserStore) Update(ctx context.Context, id uuid.UUID, userOpt *domain.UserOpt) error {

	

	return nil
}