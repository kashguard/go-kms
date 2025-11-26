package policies

import (
	"net/http"

	"github.com/go-openapi/strfmt"
	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/types/kms"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func GetPolicyRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.GET("/policies/:policyId", getPolicyHandler(s))
}

func getPolicyHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		params := kms.NewGetPolicyRouteParams()
		if err := params.BindRequest(c.Request(), nil); err != nil {
			return err
		}

		// 获取策略
		policyData, err := s.MetadataStore.GetPolicy(ctx, params.PolicyID)
		if err != nil {
			log.Error().Err(err).Str("policy_id", params.PolicyID).Msg("Failed to get policy")
			if err.Error() == errPolicyNotFound {
				return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Policy not found")
			}
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to get policy")
		}

		// 转换响应
		response := &types.GetPolicyResponse{
			PolicyID:       &policyData.PolicyID,
			PolicyDocument: policyData.PolicyDocument,
			Description:    policyData.Description,
		}
		if !policyData.CreatedAt.IsZero() {
			createdAt := strfmt.DateTime(policyData.CreatedAt)
			response.CreatedAt = createdAt
		}
		if !policyData.UpdatedAt.IsZero() {
			updatedAt := strfmt.DateTime(policyData.UpdatedAt)
			response.UpdatedAt = updatedAt
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
