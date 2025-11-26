package secrets

import (
	"encoding/base64"
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

func PostCreateSecretRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.POST("/secrets", postCreateSecretHandler(s))
}

func postCreateSecretHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		// 检查 Secret 服务是否启用
		if s.SecretService == nil {
			return httperrors.NewHTTPError(http.StatusServiceUnavailable, types.PublicHTTPErrorTypeGeneric, "Secret service is not enabled")
		}

		var body types.PostCreateSecretPayload
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		if body.KeyID == nil {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "key_id is required")
		}
		if body.Data == nil {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "data is required")
		}

		decodedData, err := base64.StdEncoding.DecodeString(body.Data.String())
		if err != nil {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "Invalid base64 data format")
		}

		// 调用服务
		keyID, err := s.SecretService.CreateSecret(ctx, *body.KeyID, decodedData)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create secret")
			if errors.Is(err, secret.ErrSecretAlreadyExists) {
				return httperrors.NewHTTPError(http.StatusConflict, types.PublicHTTPErrorTypeGeneric, "Secret already exists")
			}
			if errors.Is(err, secret.ErrInvalidKMSKey) {
				return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Invalid KMS key configuration")
			}
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to create secret")
		}

		// 获取创建的 Secret 以获取时间戳
		secretData, err := s.MetadataStore.GetSecret(ctx, keyID)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get created secret")
			// 即使获取失败，也返回成功（因为已经创建了）
		}

		// 转换响应
		response := &types.CreateSecretResponse{
			KeyID: &keyID,
		}
		if secretData != nil && !secretData.CreatedAt.IsZero() {
			response.CreatedAt = strfmt.DateTime(secretData.CreatedAt)
		}

		return util.ValidateAndReturn(c, http.StatusCreated, response)
	}
}
