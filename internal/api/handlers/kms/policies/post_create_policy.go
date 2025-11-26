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

func PostCreatePolicyRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.POST("/policies", postCreatePolicyHandler(s))
}

func postCreatePolicyHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		params := kms.NewPostCreatePolicyRouteParams()
		if err := params.BindRequest(c.Request(), nil); err != nil {
			return err
		}

		// 转换请求
		now := time.Now()

		// 转换 PolicyDocument 为 map[string]interface{}
		policyDoc, ok := params.Payload.PolicyDocument.(map[string]interface{})
		if !ok {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "Invalid policy_document format")
		}

		policyData := &storage.Policy{
			PolicyID:       *params.Payload.PolicyID,
			Description:    params.Payload.Description,
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
