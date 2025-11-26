package middleware_test

import (
	"io"
	"net/http"
	"testing"

	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/middleware"
	"github.com/kashguard/go-kms/internal/test"
	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"

	"github.com/stretchr/testify/require"
)

func TestLogErrorFuncWithRequestInfo(t *testing.T) {
	test.WithTestServer(t, func(s *api.Server) {
		path := "/testing-e87bc94c-2d1f-4342-9ec2-f158c63ac6da"

		s.Echo.Use(echoMiddleware.RecoverWithConfig(echoMiddleware.RecoverConfig{
			LogErrorFunc: middleware.LogErrorFuncWithRequestInfo,
		}))

		s.Echo.POST(path, func(c echo.Context) error {
			// trigger the recover middleware by triggering a nil pointer dereference
			var val *int
			_ = *val

			return c.NoContent(http.StatusNoContent)
		})

		res := test.PerformRequest(t, s, "POST", path, nil, nil)
		require.Equal(t, http.StatusInternalServerError, res.Result().StatusCode)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)

		test.Snapshoter.SaveString(t, string(body))
	})
}
