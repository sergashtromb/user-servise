package custerr

import "user_service/pkg/repoerrors"

const RepoName = "Redis"

var (
	ErrUserAlredyExist      = repoerrors.NewError(RepoName, "user alredy exist", "001")
	ErrFailedRollbackInedex = repoerrors.NewFatalErr(RepoName, "failed rollback index", "002")
	ErrSetIndexInRedis      = repoerrors.NewError(RepoName, "failed set index", "003")
	ErrNotFound             = repoerrors.NewError(RepoName, "value not found", "004")
	ErrBadData              = repoerrors.NewError(RepoName, "bad data", "005")
	ErrBadArgs              = repoerrors.NewError(RepoName, "bad arguments", "006")
	ErrSessionAlredyExist   = repoerrors.NewError(RepoName, "session with family id alredy exist", "007")
)
