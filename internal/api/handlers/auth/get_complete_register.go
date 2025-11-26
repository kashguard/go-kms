package auth

import (
	"net/http"

	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/router/templates"
	"github.com/kashguard/go-kms/internal/types/auth"
	"github.com/kashguard/go-kms/internal/util/url"

	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func GetCompleteRegisterRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1Auth.GET("/register", getCompleteRegisterHandler(s))
}

func getCompleteRegisterHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		params := auth.NewGetCompleteRegisterRouteParams()
		if err := util.BindAndValidatePathAndQueryParams(c, &params); err != nil {
			return err
		}

		confirmationRequestURL, err := url.ConfirmationRequestURL(s.Config, params.Token.String())
		if err != nil {
			log.Debug().Err(err).Msg("Failed to generate confirmation link")
			return err
		}

		return c.Render(http.StatusOK, templates.ViewTemplateAccountConfirmation.String(), map[string]interface{}{
			"confirmationRequestURL": confirmationRequestURL.String(),
		})
	}
}
