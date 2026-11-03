package postgres

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"user_service/pkg/repoerrors"
)

const RepoName = "Postgres"

var (
	ErrUserAlreadyExists = repoerrors.NewError(RepoName, "User already exists", "001")
	ErrFieldCantBeEmpty  = repoerrors.NewError(RepoName, "Field can't be empty", "002")
	ErrConvertQuery      = repoerrors.NewError(RepoName, "Failed convert sql from object", "003")
	ErrUserDontExist     = repoerrors.NewError(RepoName, "User don't exist", "004")

	CodeErrUniqueViolation = "23505"
)

func DbErrorFromUnicViolation(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == CodeErrUniqueViolation {
		newErr := ErrUserAlreadyExists.Clone()

		switch pgErr.ConstraintName {
		case "users_username_idx":
			newErr.Fields = append(newErr.Fields, "username")
		case "users_email_idx":
			newErr.Fields = append(newErr.Fields, "email")
		case "users_phone_idx":
			newErr.Fields = append(newErr.Fields, "phone")
		}
		return newErr
	}

	return nil
}
