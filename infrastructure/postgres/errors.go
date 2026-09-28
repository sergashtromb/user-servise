package postgres

import "fmt"

const (
	ErrUserAlreadyExists = "User already exists"
	CodeDbErrUserAlreadyExists = "001"

	CodeErrUniqueViolation = "23505"
)

type DbError struct {
	Mess 	string
	Fields 	[]string
	Code 	string
}

func NewDbError(ms string, code string, fields []string) *DbError {
	return &DbError{
		Mess: ms,
		Code: code,
		Fields: fields,
	}
}

func (de *DbError) Error() string {
	return fmt.Sprintf("DbError: CODE: %s, w: %s, f: %v\n", de.Code, de.Mess, de.Fields)
}