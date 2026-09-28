package domain

import (
	"time"
	"user_service/pkg/opt"
	"uuid"
)

type User struct {
	Id 			uuid.UUID
	UserName 	string
	Password 	string //hash summ
	Email 		string
	Phone 		string
	CreatedAt 	time.Time
	IsDeleted 	bool
}

type UserOpt struct {
	UserName 	opt.Field[string] 	`json:"username"`
	Email 		opt.Field[string] 	`json:"email"`
	Phone 		opt.Field[string] 	`json:"phone"`
	IsDeleted 	opt.Field[bool] 	`json:"is_delete"`
}

type ValueUserOpt struct {

}