package secrets

import (
	"net/http"

	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func HeadSecretExistsRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.HEAD("/secrets/:keyId", headSecretExistsHandler(s))
}

func headSecretExistsHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		// 检查 Secret 服务是否启用
		if s.SecretService == nil {
			return httperrors.NewHTTPError(http.StatusServiceUnavailable, types.PublicHTTPErrorTypeGeneric, "Secret service is not enabled")
		}

		keyID := c.Param("keyId")
		if keyID == "" {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "keyId parameter is required")
		}

		// 调用服务
		exists, err := s.SecretService.SecretExists(ctx, keyID)
		if err != nil {
			log.Error().Err(err).Msg("Failed to check secret existence")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to check secret existence")
		}

		if !exists {
			return c.NoContent(http.StatusNotFound)
		}

		return c.NoContent(http.StatusOK)
	}
}
