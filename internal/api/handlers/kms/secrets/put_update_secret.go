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
	"github.com/kashguard/go-kms/internal/types/kms"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func PutUpdateSecretRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.PUT("/secrets/:keyId", putUpdateSecretHandler(s))
}

func putUpdateSecretHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		params := kms.NewPutUpdateSecretRouteParams()
		if err := params.BindRequest(c.Request(), nil); err != nil {
			return err
		}

		// 解码 base64 数据
		if params.Payload.Data == nil {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "data is required")
		}

		decodedData, err := base64.StdEncoding.DecodeString(params.Payload.Data.String())
		if err != nil {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "Invalid base64 data format")
		}

		// 调用服务
		err = s.SecretService.UpdateSecret(ctx, params.KeyID, decodedData)
		if err != nil {
			log.Error().Err(err).Msg("Failed to update secret")
			if errors.Is(err, secret.ErrSecretNotFound) {
				return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Secret not found")
			}
			if errors.Is(err, secret.ErrInvalidKMSKey) {
				return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Invalid KMS key configuration")
			}
			if errors.Is(err, secret.ErrEncryptionFailed) {
				return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to encrypt secret")
			}
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to update secret")
		}

		// 获取更新后的 Secret 用于响应
		updatedData, err := s.SecretService.GetSecret(ctx, params.KeyID)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get updated secret")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to get updated secret")
		}

		// 获取更新后的 Secret 元数据以获取 updated_at
		secretData, err := s.MetadataStore.GetSecret(ctx, params.KeyID)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get updated secret metadata")
			// 即使获取失败，也返回数据（因为已经更新了）
		}

		// 转换响应
		dataBase64 := strfmt.Base64(updatedData)
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
