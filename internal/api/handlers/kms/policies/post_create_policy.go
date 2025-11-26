package policies

import (
	"net/http"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/kms/storage"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func PostCreatePolicyRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.POST("/policies", postCreatePolicyHandler(s))
}

func postCreatePolicyHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		var body types.PostCreatePolicyPayload
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		// 转换请求
		now := time.Now()

		if body.PolicyID == nil {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "policy_id is required")
		}

		// 转换 PolicyDocument 为 map[string]interface{}
		policyDoc, ok := body.PolicyDocument.(map[string]interface{})
		if !ok {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "Invalid policy_document format")
		}

		policyData := &storage.Policy{
			PolicyID:       *body.PolicyID,
			Description:    body.Description,
			PolicyDocument: policyDoc,
			CreatedAt:      now,
			UpdatedAt:      now,
		}

		// 保存策略
		if err := s.MetadataStore.SavePolicy(ctx, policyData); err != nil {
			log.Error().Err(err).Msg("Failed to save policy")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to create policy")
		}

		// 转换响应
		response := &types.CreatePolicyResponse{
			PolicyID:    &policyData.PolicyID,
			Description: policyData.Description,
		}
		if !policyData.CreatedAt.IsZero() {
			createdAt := strfmt.DateTime(policyData.CreatedAt)
			response.CreatedAt = createdAt
		}
		if !policyData.UpdatedAt.IsZero() {
			updatedAt := strfmt.DateTime(policyData.UpdatedAt)
			response.UpdatedAt = updatedAt
		}

		return util.ValidateAndReturn(c, http.StatusCreated, response)
	}
}
