package security

import (
	"github.com/labstack/echo"
)

func NewSecurityMiddleware(ah *AuthenticationHandler) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if err := ah.Handle(c.Request()); err != nil {
				return err
			}
			return next(c)
		}
	}
}
