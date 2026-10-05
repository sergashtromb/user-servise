package postgres

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

// FIXME change on pkg errors
const (
	ErrUserAlreadyExists       = "User already exists"
	CodeDbErrUserAlreadyExists = "001"

	ErrFieldCantBeEmpty       = "Field can't be empty"
	CodeDbErrFieldCantBeEmpty = "002"

	ErrConvertQuery       = "Failed convert sql from object"
	CodeDbErrConvertQuery = "003"

	ErrUserDontExist       = "User don't exist"
	CodeDbErrUserDontExist = "004"

	CodeErrUniqueViolation = "23505"
)

type DbError struct {
	Mess   string
	Fields []string
	Code   string
}

func NewDbError(ms string, code string, fields []string) *DbError {
	return &DbError{
		Mess:   ms,
		Code:   code,
		Fields: fields,
	}
}

func (de *DbError) Error() string {
	return fmt.Sprintf("DbError: CODE: %s, w: %s, f: %v\n", de.Code, de.Mess, de.Fields)
}

func DbErrorFromUnicViolation(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == CodeErrUniqueViolation {

		newDbErr := NewDbError(ErrUserAlreadyExists, CodeDbErrUserAlreadyExists, make([]string, 0))

		switch pgErr.ConstraintName {
		case "users_username_idx":
			newDbErr.Fields = append(newDbErr.Fields, "username")
		case "users_email_idx":
			newDbErr.Fields = append(newDbErr.Fields, "email")
		case "users_phone_idx":
			newDbErr.Fields = append(newDbErr.Fields, "phone")
		}
		return newDbErr
	}

	return nil
}
