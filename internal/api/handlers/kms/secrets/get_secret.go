package secrets

import (
	"errors"
	"net/http"

	"github.com/go-openapi/strfmt"
	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/kms/secret"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/types/kms"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func GetSecretRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.GET("/secrets/:keyId", getSecretHandler(s))
}

func getSecretHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		params := kms.NewGetSecretRouteParams()
		if err := params.BindRequest(c.Request(), nil); err != nil {
			return err
		}

		// 调用服务
		data, err := s.SecretService.GetSecret(ctx, params.KeyID)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get secret")
			if errors.Is(err, secret.ErrSecretNotFound) {
				return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Secret not found")
			}
			if errors.Is(err, secret.ErrInvalidKMSKey) {
				return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Invalid KMS key configuration")
			}
			if errors.Is(err, secret.ErrDecryptionFailed) {
				return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to decrypt secret")
			}
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to get secret")
		}

		// 获取 Secret 元数据以获取 updated_at
		secretData, err := s.MetadataStore.GetSecret(ctx, params.KeyID)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get secret metadata")
			// 即使获取失败，也返回数据（因为已经解密了）
		}

		// 转换响应
		dataBase64 := strfmt.Base64(data)
		response := &types.GetSecretResponse{
			KeyID: &params.KeyID,
			Data:  &dataBase64,
		}
		if secretData != nil && !secretData.UpdatedAt.IsZero() {
			response.UpdatedAt = strfmt.DateTime(secretData.UpdatedAt)
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
