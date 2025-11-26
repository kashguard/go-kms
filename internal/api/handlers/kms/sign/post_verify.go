package sign

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/go-openapi/swag"
	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/kms/key"
	"github.com/kashguard/go-kms/internal/kms/sign"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func PostVerifyRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.POST("/verify", postVerifyHandler(s))
}

func postVerifyHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		var body types.PostVerifyPayload
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		// 解码消息和签名
		if body.Message == nil {
			return httperrors.NewHTTPValidationError(
				http.StatusBadRequest,
				types.PublicHTTPErrorTypeGeneric,
				"Invalid request",
				[]*types.HTTPValidationErrorDetail{
					{
						Key:   swag.String("message"),
						In:    swag.String("body"),
						Error: swag.String("message is required"),
					},
				},
			)
		}

		message, err := base64.StdEncoding.DecodeString(body.Message.String())
		if err != nil {
			return httperrors.NewHTTPValidationError(
				http.StatusBadRequest,
				types.PublicHTTPErrorTypeGeneric,
				"Invalid message format",
				[]*types.HTTPValidationErrorDetail{
					{
						Key:   swag.String("message"),
						In:    swag.String("body"),
						Error: swag.String("must be base64 encoded"),
					},
				},
			)
		}

		if body.Signature == nil {
			return httperrors.NewHTTPValidationError(
				http.StatusBadRequest,
				types.PublicHTTPErrorTypeGeneric,
				"Invalid request",
				[]*types.HTTPValidationErrorDetail{
					{
						Key:   swag.String("signature"),
						In:    swag.String("body"),
						Error: swag.String("signature is required"),
					},
				},
			)
		}

		signature, err := base64.StdEncoding.DecodeString(body.Signature.String())
		if err != nil {
			return httperrors.NewHTTPValidationError(
				http.StatusBadRequest,
				types.PublicHTTPErrorTypeGeneric,
				"Invalid signature format",
				[]*types.HTTPValidationErrorDetail{
					{
						Key:   swag.String("signature"),
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
		if body.Algorithm == nil {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "algorithm is required")
		}

		mode := "DIGEST"
		if body.Mode != nil {
			mode = *body.Mode
		}

		req := &sign.VerifyRequest{
			KeyID:     *body.KeyID,
			Message:   message,
			Signature: signature,
			Algorithm: *body.Algorithm,
			Mode:      mode,
		}

		// 调用服务
		resp, err := s.SignService.Verify(ctx, req)
		if err != nil {
			log.Error().Err(err).Msg("Failed to verify signature")
			if errors.Is(err, key.ErrKeyNotFound) {
				return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Key not found")
			}
			if errors.Is(err, sign.ErrInvalidKeyType) {
				return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "Invalid key type for verification")
			}
			if errors.Is(err, sign.ErrInvalidAlgorithm) {
				return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "Invalid signing algorithm")
			}
			if errors.Is(err, sign.ErrInvalidSignature) {
				return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "Invalid signature")
			}
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to verify signature")
		}

		// 转换响应
		keyVersion := int64(resp.KeyVersion)
		response := &types.PostVerifyResponse{
			Valid:      &resp.Valid,
			KeyID:      &resp.KeyID,
			KeyVersion: keyVersion,
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
