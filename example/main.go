package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	sharedSecurity "github.com/ivan-prykhodko/go-security"
	"github.com/ivan-prykhodko/go-security/example/app/api/resource"
	"github.com/ivan-prykhodko/go-security/example/app/config"
	"github.com/labstack/echo"
)

func main() {
	srv := echo.New()
	srv.Debug = true
	srv.HTTPErrorHandler = func(err error, c echo.Context) {
		var httpError sharedSecurity.HttpError
		if errors.As(err, &httpError) {
			_ = c.JSON(httpError.StatusCode(), map[string]interface{}{
				"error": httpError.Error(),
			})
			return
		}
	}

	mws := []echo.MiddlewareFunc{
		config.NewHttpSecurityMiddleware(),
	}
	for _, mfn := range mws {
		srv.Use(mfn)
	}

	privateRouter := srv.Group("/private")
	privateRouter.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "I'm alive!",
		})
	})

	pubRouter := srv.Group("/public")
	pubRouter.GET("/docs/100500", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"title":       "Doc-100500",
			"description": "Doc-description",
		})
	})

	clRouter := srv.Group("/api/clients")
	clRouter.GET("/100500", func(c echo.Context) error {
		sctx := sharedSecurity.GetSecurityContextFromRequest(c.Request())
		if !sctx.IsGranted("VIEW", resource.ClientResource{}) {
			fmt.Println("User is not allowed to view client")
			return sharedSecurity.AccessDeniedError
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"id":   100500,
			"name": "Bob",
		})
	})
	clRouter.PATCH("/100500", func(c echo.Context) error {
		sctx := sharedSecurity.GetSecurityContextFromRequest(c.Request())
		if !sctx.IsGranted("EDIT", resource.ClientResource{}) {
			fmt.Println("User is not allowed to edit client")
			return sharedSecurity.AccessDeniedError
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"id":   100500,
			"name": "Bob updated",
		})
	})

	go func() {
		if err := srv.Start(":8080"); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srv.Logger.Fatal(err)
		}
	}()

	quit := make(chan os.Signal, 1)

	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutdown Server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Println("Server Shutdown:", err)
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		log.Println("Shutdown timed out")
	}

	log.Println("Server exiting")
}
