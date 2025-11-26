package keys

import (
	"net/http"
	"strconv"

	"github.com/go-openapi/strfmt"
	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/kms/key"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func GetListKeysRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.GET("/keys", getListKeysHandler(s))
}

func getListKeysHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		// 解析查询参数
		filter := &key.KeyFilter{
			State:   c.QueryParam("state"),
			KeyType: c.QueryParam("key_type"),
			Alias:   c.QueryParam("alias"),
		}

		if limitStr := c.QueryParam("limit"); limitStr != "" {
			if limit, err := strconv.Atoi(limitStr); err == nil {
				filter.Limit = limit
			}
		}
		if offsetStr := c.QueryParam("offset"); offsetStr != "" {
			if offset, err := strconv.Atoi(offsetStr); err == nil {
				filter.Offset = offset
			}
		}

		// 调用服务
		keys, err := s.KeyService.ListKeys(ctx, filter)
		if err != nil {
			log.Error().Err(err).Msg("Failed to list keys")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to list keys")
		}

		// 转换响应
		keyResponses := make([]*types.GetKeyResponse, 0, len(keys))
		for _, keyMetadata := range keys {
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

			keyResponses = append(keyResponses, response)
		}

		listResponse := &types.ListKeysResponse{
			Keys:  keyResponses,
			Total: int64(len(keyResponses)),
		}

		return util.ValidateAndReturn(c, http.StatusOK, listResponse)
	}
}
