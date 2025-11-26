package auth

import (
	"net/http"

	"github.com/go-openapi/swag"
	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/data/dto"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func PostLoginRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1Auth.POST("/login", postLoginHandler(s))
}

func postLoginHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		var body types.PostLoginPayload
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		result, err := s.Auth.Login(ctx, dto.LoginRequest{
			Username: dto.NewUsername(body.Username.String()),
			Password: swag.StringValue(body.Password),
		})
		if err != nil {
			log.Debug().Err(err).Msg("Failed to authenticate user")
			return err
		}

		return util.ValidateAndReturn(c, http.StatusOK, result.ToTypes())
	}
}
