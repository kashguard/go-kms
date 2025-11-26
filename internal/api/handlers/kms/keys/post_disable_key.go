//nolint:dupl // post_enable_key.go and post_disable_key.go are intentionally similar
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

func PostDisableKeyRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.POST("/keys/:keyId/disable", postDisableKeyHandler(s))
}

func postDisableKeyHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		keyID := c.Param("keyId")
		if keyID == "" {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "keyId parameter is required")
		}

		// 调用服务
		if err := s.KeyService.DisableKey(ctx, keyID); err != nil {
			log.Error().Err(err).Msg("Failed to disable key")
			if errors.Is(err, key.ErrKeyNotFound) {
				return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Key not found")
			}
			if errors.Is(err, key.ErrKeyDeleted) {
				return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "Key is deleted")
			}
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to disable key")
		}

		// 获取更新后的密钥
		keyMetadata, err := s.KeyService.GetKey(ctx, keyID)
		if err != nil {
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to get updated key")
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
