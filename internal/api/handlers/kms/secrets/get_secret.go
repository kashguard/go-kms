package secrets

import (
	"errors"
	"net/http"

	"github.com/go-openapi/strfmt"
	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/kms/secret"
	"github.com/kashguard/go-kms/internal/types"
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

		// 检查 Secret 服务是否启用
		if s.SecretService == nil {
			return httperrors.NewHTTPError(http.StatusServiceUnavailable, types.PublicHTTPErrorTypeGeneric, "Secret service is not enabled")
		}

		keyID := c.Param("keyId")
		if keyID == "" {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "keyId parameter is required")
		}

		// 调用服务
		data, err := s.SecretService.GetSecret(ctx, keyID)
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
		secretData, err := s.MetadataStore.GetSecret(ctx, keyID)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get secret metadata")
			// 即使获取失败，也返回数据（因为已经解密了）
		}

		// 转换响应
		dataBase64 := strfmt.Base64(data)
		response := &types.GetSecretResponse{
			KeyID: &keyID,
			Data:  &dataBase64,
		}
		if secretData != nil && !secretData.UpdatedAt.IsZero() {
			response.UpdatedAt = strfmt.DateTime(secretData.UpdatedAt)
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
