package sign

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/kms/key"
	"github.com/kashguard/go-kms/internal/kms/sign"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func PostSignRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.POST("/sign", postSignHandler(s))
}

func postSignHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		var body types.PostSignPayload
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		// 解码消息
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

		req := &sign.SignRequest{
			KeyID:     *body.KeyID,
			Message:   message,
			Algorithm: *body.Algorithm,
			Mode:      mode,
		}

		// 调用服务
		resp, err := s.SignService.Sign(ctx, req)
		if err != nil {
			log.Error().Err(err).Msg("Failed to sign")
			if errors.Is(err, key.ErrKeyNotFound) {
				return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Key not found")
			}
			if errors.Is(err, sign.ErrKeyDisabled) {
				return httperrors.NewHTTPError(http.StatusForbidden, types.PublicHTTPErrorTypeGeneric, "Key is disabled")
			}
			if errors.Is(err, sign.ErrInvalidKeyType) {
				return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "Invalid key type for signing")
			}
			if errors.Is(err, sign.ErrInvalidAlgorithm) {
				return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "Invalid signing algorithm")
			}
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to sign")
		}

		// 转换响应
		signatureStr := strfmt.Base64(resp.Signature)
		keyVersion := int64(resp.KeyVersion)
		response := &types.PostSignResponse{
			Signature:  &signatureStr,
			KeyID:      &resp.KeyID,
			KeyVersion: keyVersion,
			Algorithm:  resp.Algorithm,
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
