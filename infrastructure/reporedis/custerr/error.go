package custerr

import "user_service/pkg/repoerrors"

const RepoName = "Redis"

var (
	ErrUserAlredyExist          = repoerrors.NewError(RepoName, "user alredy exist", "001")
	ErrFailedRollbackInedex     = repoerrors.NewFatalErr(RepoName, "failed rollback index", "002")
	ErrSetIndexInRedis          = repoerrors.NewError(RepoName, "failed set index", "003")
	ErrNotFound                 = repoerrors.NewError(RepoName, "value not found", "004")
	ErrBadData                  = repoerrors.NewError(RepoName, "bad data", "005")
	ErrBadArgs                  = repoerrors.NewError(RepoName, "bad arguments", "006")
	ErrSessionAlredyExist       = repoerrors.NewError(RepoName, "session with family id alredy exist", "007")
	ErrSuspiciousRefreshRate    = repoerrors.NewError(RepoName, "suspicious update frequency", "008")
	ErrGracePeriodicAlredyExist = repoerrors.NewError(RepoName, "grace periodic alredy exist", "009")
	ErrGracePeriodicVersionMiss = repoerrors.NewError(RepoName, "grace periodic version mismatch", "010")
	ErrGracePeriodicNoExists    = repoerrors.NewError(RepoName, "grace periodic no exists", "011")
)
