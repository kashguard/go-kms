package secrets

import (
	"net/http"

	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/types/kms"
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

		params := kms.NewHeadSecretExistsRouteParams()
		if err := params.BindRequest(c.Request(), nil); err != nil {
			return err
		}

		// 调用服务
		exists, err := s.SecretService.SecretExists(ctx, params.KeyID)
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
