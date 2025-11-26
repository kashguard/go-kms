package encryption

import (
	"encoding/base64"
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

func PostEncryptRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.POST("/encrypt", postEncryptHandler(s))
}

func postEncryptHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		var body types.PostEncryptPayload
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		// 解码明文
		if body.Plaintext == nil {
			return httperrors.NewHTTPValidationError(
				http.StatusBadRequest,
				types.PublicHTTPErrorTypeGeneric,
				"Invalid request",
				[]*types.HTTPValidationErrorDetail{
					{
						Key:   swag.String("plaintext"),
						In:    swag.String("body"),
						Error: swag.String("plaintext is required"),
					},
				},
			)
		}

		plaintext, err := base64.StdEncoding.DecodeString(body.Plaintext.String())
		if err != nil {
			return httperrors.NewHTTPValidationError(
				http.StatusBadRequest,
				types.PublicHTTPErrorTypeGeneric,
				"Invalid plaintext format",
				[]*types.HTTPValidationErrorDetail{
					{
						Key:   swag.String("plaintext"),
						In:    swag.String("body"),
						Error: swag.String("must be base64 encoded"),
					},
				},
			)
		}

		// 转换请求
		if body.KeyID == nil {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "key_id is required")
		}

		req := &encryption.EncryptRequest{
			KeyID:             *body.KeyID,
			Plaintext:         plaintext,
			EncryptionContext: body.EncryptionContext,
		}

		// 调用服务
		resp, err := s.EncryptionService.Encrypt(ctx, req)
		if err != nil {
			log.Error().Err(err).Msg("Failed to encrypt")
			if errors.Is(err, key.ErrKeyNotFound) {
				return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Key not found")
			}
			if errors.Is(err, encryption.ErrKeyDisabled) {
				return httperrors.NewHTTPError(http.StatusForbidden, types.PublicHTTPErrorTypeGeneric, "Key is disabled")
			}
			if errors.Is(err, encryption.ErrInvalidKeyType) {
				return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "Invalid key type for encryption")
			}
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to encrypt")
		}

		// 转换响应
		ciphertextStr := strfmt.Base64(resp.CiphertextBlob)
		keyVersion := int64(resp.KeyVersion)
		response := &types.PostEncryptResponse{
			CiphertextBlob: &ciphertextStr,
			KeyID:          &resp.KeyID,
			KeyVersion:     keyVersion,
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
