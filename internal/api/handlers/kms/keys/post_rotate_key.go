package keys

import (
	"errors"
	"net/http"

	"github.com/go-openapi/strfmt"
	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/kms/key"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func PostRotateKeyRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.POST("/keys/:keyId/rotate", postRotateKeyHandler(s))
}

func postRotateKeyHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		keyID := c.Param("keyId")
		if keyID == "" {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "keyId parameter is required")
		}

		// 调用服务
		keyMetadata, err := s.KeyService.RotateKey(ctx, keyID)
		if err != nil {
			log.Error().Err(err).Msg("Failed to rotate key")
			if errors.Is(err, key.ErrKeyNotFound) {
				return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Key not found")
			}
			if errors.Is(err, key.ErrPolicyDenied) {
				return httperrors.NewHTTPError(http.StatusForbidden, types.PublicHTTPErrorTypeGeneric, "Policy denied")
			}
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to rotate key")
		}

		// 转换响应
		latestVersion := int64(keyMetadata.LatestVersion)
		response := &types.GetKeyResponse{
			KeyID:         &keyMetadata.KeyID,
			Alias:         keyMetadata.Alias,
			Description:   keyMetadata.Description,
			KeyType:       (*string)(&keyMetadata.KeyType),
			KeyState:      (*string)(&keyMetadata.KeyState),
			LatestVersion: latestVersion,
			Tags:          keyMetadata.Tags,
		}

		if !keyMetadata.CreatedAt.IsZero() {
			createdAt := strfmt.DateTime(keyMetadata.CreatedAt)
			response.CreatedAt = createdAt
		}
		if !keyMetadata.UpdatedAt.IsZero() {
			updatedAt := strfmt.DateTime(keyMetadata.UpdatedAt)
			response.UpdatedAt = updatedAt
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
