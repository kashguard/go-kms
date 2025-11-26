package policies

import (
	"net/http"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/kms/storage"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/types/kms"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func PutUpdatePolicyRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.PUT("/policies/:policyId", putUpdatePolicyHandler(s))
}

func putUpdatePolicyHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		params := kms.NewPutUpdatePolicyRouteParams()
		if err := params.BindRequest(c.Request(), nil); err != nil {
			return err
		}

		// 获取现有策略
		existingPolicy, err := s.MetadataStore.GetPolicy(ctx, params.PolicyID)
		if err != nil {
			log.Error().Err(err).Str("policy_id", params.PolicyID).Msg("Failed to get policy")
			if err.Error() == errPolicyNotFound {
				return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Policy not found")
			}
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to get policy")
		}

		// 更新策略
		updatedPolicy := &storage.Policy{
			PolicyID:       existingPolicy.PolicyID,
			Description:    existingPolicy.Description,
			PolicyDocument: existingPolicy.PolicyDocument,
			CreatedAt:      existingPolicy.CreatedAt,
			UpdatedAt:      time.Now(),
		}

		if params.Payload.Description != "" {
			updatedPolicy.Description = params.Payload.Description
		}
		if params.Payload.PolicyDocument != nil {
			// 转换 PolicyDocument 为 map[string]interface{}
			policyDoc, ok := params.Payload.PolicyDocument.(map[string]interface{})
			if !ok {
				return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "Invalid policy_document format")
			}
			updatedPolicy.PolicyDocument = policyDoc
		}

		if err := s.MetadataStore.UpdatePolicy(ctx, params.PolicyID, updatedPolicy); err != nil {
			log.Error().Err(err).Str("policy_id", params.PolicyID).Msg("Failed to update policy")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to update policy")
		}

		// 转换响应
		response := &types.GetPolicyResponse{
			PolicyID:       &updatedPolicy.PolicyID,
			PolicyDocument: updatedPolicy.PolicyDocument,
			Description:    updatedPolicy.Description,
		}
		if !updatedPolicy.CreatedAt.IsZero() {
			createdAt := strfmt.DateTime(updatedPolicy.CreatedAt)
			response.CreatedAt = createdAt
		}
		if !updatedPolicy.UpdatedAt.IsZero() {
			updatedAt := strfmt.DateTime(updatedPolicy.UpdatedAt)
			response.UpdatedAt = updatedAt
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
