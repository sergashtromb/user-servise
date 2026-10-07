package custerr

import "user_service/pkg/repoerrors"

const RepoName = "Redis"

var (
	ErrUserAlredyExist      = repoerrors.NewError(RepoName, "user alredy exist", "001")
	ErrFailedRollbackInedex = repoerrors.NewFatalErr(RepoName, "failed rollback index", "002")
	ErrSetIndexInRedis      = repoerrors.NewError(RepoName, "failed set index", "003")
)
