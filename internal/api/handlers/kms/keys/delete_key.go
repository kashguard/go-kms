package keys

import (
	"errors"
	"net/http"

	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/kms/key"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func DeleteKeyRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.DELETE("/keys/:keyId", deleteKeyHandler(s))
}

func deleteKeyHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		keyID := c.Param("keyId")
		if keyID == "" {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "keyId parameter is required")
		}

		// 调用服务
		if err := s.KeyService.DeleteKey(ctx, keyID); err != nil {
			log.Error().Err(err).Msg("Failed to delete key")
			if errors.Is(err, key.ErrKeyNotFound) {
				return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Key not found")
			}
			if errors.Is(err, key.ErrPolicyDenied) {
				return httperrors.NewHTTPError(http.StatusForbidden, types.PublicHTTPErrorTypeGeneric, "Policy denied")
			}
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to delete key")
		}

		return c.NoContent(http.StatusNoContent)
	}
}
