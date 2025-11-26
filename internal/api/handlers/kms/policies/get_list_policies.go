package policies

import (
	"net/http"

	"github.com/go-openapi/strfmt"
	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func GetListPoliciesRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.GET("/policies", getListPoliciesHandler(s))
}

func getListPoliciesHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		// 列出所有策略
		policies, err := s.MetadataStore.ListPolicies(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Failed to list policies")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to list policies")
		}

		// 转换响应
		policyResponses := make([]*types.GetPolicyResponse, 0, len(policies))
		for _, policyData := range policies {
			response := &types.GetPolicyResponse{
				PolicyID:       &policyData.PolicyID,
				PolicyDocument: policyData.PolicyDocument,
				Description:    policyData.Description,
			}
			if !policyData.CreatedAt.IsZero() {
				response.CreatedAt = strfmt.DateTime(policyData.CreatedAt)
			}
			if !policyData.UpdatedAt.IsZero() {
				response.UpdatedAt = strfmt.DateTime(policyData.UpdatedAt)
			}
			policyResponses = append(policyResponses, response)
		}

		total := int64(len(policyResponses))
		response := &types.ListPoliciesResponse{
			Policies: policyResponses,
			Total:    total,
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
