package keys

import (
	"errors"
	"net/http"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/kms/key"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/types/kms"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func PostCreateKeyRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.POST("/keys", postCreateKeyHandler(s))
}

func postCreateKeyHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		params := kms.NewPostCreateKeyRouteParams()
		if err := params.BindRequest(c.Request(), nil); err != nil {
			return err
		}

		// 转换请求
		req := &key.CreateKeyRequest{
			Alias:       params.Payload.Alias,
			Description: params.Payload.Description,
			KeyType:     key.KeyType(*params.Payload.KeyType),
			Tags:        params.Payload.Tags,
			PolicyID:    params.Payload.PolicyID,
		}

		if params.Payload.KeySpec != nil {
			req.KeySpec = &key.KeySpec{
				Algorithm:  params.Payload.KeySpec.Algorithm,
				KeySize:    int(params.Payload.KeySpec.KeySize),
				Curve:      params.Payload.KeySpec.Curve,
				Attributes: params.Payload.KeySpec.Attributes,
			}
		}

		// 调用服务
		keyMetadata, err := s.KeyService.CreateKey(ctx, req)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create key")
			if errors.Is(err, key.ErrInvalidKeyType) {
				return httperrors.NewHTTPValidationError(
					http.StatusBadRequest,
					types.PublicHTTPErrorTypeGeneric,
					"Invalid key type",
					[]*types.HTTPValidationErrorDetail{
						{
							Key:   swag.String("key_type"),
							In:    swag.String("body"),
							Error: swag.String("must be one of: ECC_SECP256K1, ECC_P256, ED25519, AES_256"),
						},
					},
				)
			}
			if errors.Is(err, key.ErrPolicyDenied) {
				return httperrors.NewHTTPError(http.StatusForbidden, types.PublicHTTPErrorTypeGeneric, "Policy denied")
			}
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to create key")
		}

		// 转换响应
		response := &types.CreateKeyResponse{
			KeyID:       &keyMetadata.KeyID,
			Alias:       keyMetadata.Alias,
			Description: keyMetadata.Description,
			KeyType:     (*string)(&keyMetadata.KeyType),
			KeyState:    (*string)(&keyMetadata.KeyState),
			Tags:        keyMetadata.Tags,
		}

		if !keyMetadata.CreatedAt.IsZero() {
			createdAt := strfmt.DateTime(keyMetadata.CreatedAt)
			response.CreatedAt = createdAt
		}
		if !keyMetadata.UpdatedAt.IsZero() {
			updatedAt := strfmt.DateTime(keyMetadata.UpdatedAt)
			response.UpdatedAt = updatedAt
		}

		return util.ValidateAndReturn(c, http.StatusCreated, response)
	}
}
