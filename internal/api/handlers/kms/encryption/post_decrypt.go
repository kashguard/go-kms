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

func PostDecryptRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.POST("/decrypt", postDecryptHandler(s))
}

func postDecryptHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		var body types.PostDecryptPayload
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		// 解码密文
		if body.CiphertextBlob == nil {
			return httperrors.NewHTTPValidationError(
				http.StatusBadRequest,
				types.PublicHTTPErrorTypeGeneric,
				"Invalid request",
				[]*types.HTTPValidationErrorDetail{
					{
						Key:   swag.String("ciphertext_blob"),
						In:    swag.String("body"),
						Error: swag.String("ciphertext_blob is required"),
					},
				},
			)
		}

		ciphertextBlob, err := base64.StdEncoding.DecodeString(body.CiphertextBlob.String())
		if err != nil {
			return httperrors.NewHTTPValidationError(
				http.StatusBadRequest,
				types.PublicHTTPErrorTypeGeneric,
				"Invalid ciphertext format",
				[]*types.HTTPValidationErrorDetail{
					{
						Key:   swag.String("ciphertext_blob"),
						In:    swag.String("body"),
						Error: swag.String("must be base64 encoded"),
					},
				},
			)
		}

		// 转换请求
		req := &encryption.DecryptRequest{
			CiphertextBlob:    ciphertextBlob,
			EncryptionContext: body.EncryptionContext,
		}

		// 调用服务
		resp, err := s.EncryptionService.Decrypt(ctx, req)
		if err != nil {
			log.Error().Err(err).Msg("Failed to decrypt")
			if errors.Is(err, key.ErrKeyNotFound) {
				return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Key not found")
			}
			if errors.Is(err, encryption.ErrInvalidCiphertext) {
				return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "Invalid ciphertext")
			}
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to decrypt")
		}

		// 转换响应
		plaintextStr := strfmt.Base64(resp.Plaintext)
		keyVersion := int64(resp.KeyVersion)
		response := &types.PostDecryptResponse{
			Plaintext:  &plaintextStr,
			KeyID:      &resp.KeyID,
			KeyVersion: keyVersion,
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
