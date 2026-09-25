package domain

import (
	"time"
	"uuid"
)

type User struct {
	Id 			uuid.UUID
	UserName 	string
	Password 	string //hash summ
	Email 		string
	Phone 		string
	CreatedAt 	time.Time
	IsDelete 	bool
}

type UserOpt struct {
	UserName 	*string
	Email 		*string
	Phone 		*string
	IsDelete 	*bool
}
