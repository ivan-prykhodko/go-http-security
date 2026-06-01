package security

import (
	"errors"
	"net/http"
)

var (
	FirewallMissingError   = NewHttpError(http.StatusInternalServerError, errors.New("the firewall config is missed"))
	UserNotFoundError      = NewHttpError(http.StatusUnauthorized, errors.New("the user is not found"))
	AccessDeniedError      = NewHttpError(http.StatusForbidden, errors.New("access denied"))
	UserBadgeNotFountError = NewHttpError(http.StatusInternalServerError, errors.New("user badge not found in passport"))
)

type HttpError interface {
	error
	StatusCode() int
}

type httpError struct {
	statusCode int
	err        error
}

func NewHttpError(code int, err error) HttpError {
	return &httpError{
		statusCode: code,
		err:        err,
	}
}

func (e *httpError) StatusCode() int {
	return e.statusCode
}

func (e *httpError) Unwrap() error {
	return e.err
}

func (e *httpError) Error() string {
	if e.err == nil {
		return http.StatusText(e.statusCode)
	}
	return e.err.Error()
}
