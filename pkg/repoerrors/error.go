package repoerrors

import (
	"fmt"
)

type RepoError struct {
	IsFatal  bool
	Fields   []string
	RepoName string
	Mess     string
	Code     string
}

func (re *RepoError) Error() string {
	if re.IsFatal {
		return fmt.Sprintf("FATAL: r:%v code:%v mes:%v\n", re.RepoName, re.Code, re.Mess)
	}
	return fmt.Sprintf("Repo err: r:%v code:%v mes:%v\n", re.RepoName, re.Code, re.Mess)
}

func (re *RepoError) Clone() *RepoError {

	newerr := *re

	if re.Fields != nil {

		newerr.Fields = make([]string, 0, len(re.Fields))
		copy(newerr.Fields, re.Fields)
	}

	return &newerr
}

func NewFatalErr(repoName, mess, code string) *RepoError {
	return &RepoError{
		IsFatal:  true,
		RepoName: repoName,
		Mess:     mess,
		Code:     code,
	}
}

func NewFatalErrWithFields(repoName, mess, code string, fields ...string) *RepoError {
	return &RepoError{
		IsFatal:  true,
		Fields:   fields,
		RepoName: repoName,
		Mess:     mess,
		Code:     code,
	}
}

func NewError(repoName, mess, code string) *RepoError {
	return &RepoError{
		IsFatal:  false,
		RepoName: repoName,
		Mess:     mess,
		Code:     code,
	}
}

func NewErrorWithFields(repoName, mess, code string, fields ...string) *RepoError {
	return &RepoError{
		IsFatal:  false,
		Fields:   fields,
		RepoName: repoName,
		Mess:     mess,
		Code:     code,
	}
}
