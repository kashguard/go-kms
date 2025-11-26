package push

import (
	"net/http"

	"github.com/aarondl/null/v8"
	"github.com/go-openapi/swag"
	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/auth"
	"github.com/kashguard/go-kms/internal/data/dto"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func PutUpdatePushTokenRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1Push.PUT("/token", putUpdatePushTokenHandler(s))
}

func putUpdatePushTokenHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		user := auth.UserFromEchoContext(c)
		log := util.LogFromContext(ctx)

		var body types.PutUpdatePushTokenPayload
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		err := s.Local.UpdatePushToken(ctx, dto.UpdatePushTokenRequest{
			User:          *user,
			Token:         swag.StringValue(body.NewToken),
			Provider:      swag.StringValue(body.Provider),
			ExistingToken: null.StringFromPtr(body.OldToken),
		})
		if err != nil {
			log.Debug().Err(err).Msg("Failed to update push token")
			return err
		}

		return c.String(http.StatusOK, "Success")
	}
}
