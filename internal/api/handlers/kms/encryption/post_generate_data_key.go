package encryption

import (
	"errors"
	"net/http"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/kms/encryption"
	"github.com/kashguard/go-kms/internal/kms/key"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func PostGenerateDataKeyRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.POST("/generate-data-key", postGenerateDataKeyHandler(s))
}

func postGenerateDataKeyHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		var body types.PostGenerateDataKeyPayload
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		// 转换请求
		if body.KeyID == nil {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "key_id is required")
		}

		req := &encryption.GenerateDataKeyRequest{
			KeyID:             *body.KeyID,
			KeySpec:           body.KeySpec,
			NumberOfBytes:     int(body.NumberOfBytes),
			EncryptionContext: body.EncryptionContext,
			ReturnPlaintext:   swag.BoolValue(body.ReturnPlaintext),
		}

		// 调用服务
		resp, err := s.EncryptionService.GenerateDataKey(ctx, req)
		if err != nil {
			log.Error().Err(err).Msg("Failed to generate data key")
			if errors.Is(err, key.ErrKeyNotFound) {
				return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Key not found")
			}
			if errors.Is(err, encryption.ErrKeyDisabled) {
				return httperrors.NewHTTPError(http.StatusForbidden, types.PublicHTTPErrorTypeGeneric, "Key is disabled")
			}
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to generate data key")
		}

		// 转换响应
		ciphertextStr := strfmt.Base64(resp.CiphertextBlob)
		response := &types.PostGenerateDataKeyResponse{
			CiphertextBlob: &ciphertextStr,
			KeyID:          &resp.KeyID,
		}

		if len(resp.Plaintext) > 0 {
			plaintextStr := strfmt.Base64(resp.Plaintext)
			response.Plaintext = plaintextStr
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
