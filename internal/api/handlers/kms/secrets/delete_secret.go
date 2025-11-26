package secrets

import (
	"errors"
	"net/http"

	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/kms/secret"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/types/kms"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func DeleteSecretRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.DELETE("/secrets/:keyId", deleteSecretHandler(s))
}

func deleteSecretHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		params := kms.NewDeleteSecretRouteParams()
		if err := params.BindRequest(c.Request(), nil); err != nil {
			return err
		}

		// 调用服务
		err := s.SecretService.DeleteSecret(ctx, params.KeyID)
		if err != nil {
			log.Error().Err(err).Msg("Failed to delete secret")
			if errors.Is(err, secret.ErrSecretNotFound) {
				return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Secret not found")
			}
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to delete secret")
		}

		return c.NoContent(http.StatusNoContent)
	}
}
