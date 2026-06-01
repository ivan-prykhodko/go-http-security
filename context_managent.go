package security

import (
	"context"
	"net/http"
)

const RequestParamName = "_security"

type contextManager struct {
	authorizationChecker AuthorizationChecker
}

func newContextManager(authorizationChecker AuthorizationChecker) contextManager {
	return contextManager{
		authorizationChecker: authorizationChecker,
	}
}

func (m contextManager) create() SecurityContext {
	return NewSecurityContext(NewTokenStorage(), m.authorizationChecker)
}

func (m contextManager) save(ctx SecurityContext, r *http.Request) {
	requestContext := r.Context()
	requestContext = context.WithValue(requestContext, RequestParamName, ctx)
	*r = *r.WithContext(requestContext)
}

func GetSecurityContextFromRequest(r *http.Request) SecurityContext {
	requestContext := r.Context()

	ctxAny := requestContext.Value(RequestParamName)
	if ctxAny == nil {
		return nil
	}

	return ctxAny.(SecurityContext)
}
