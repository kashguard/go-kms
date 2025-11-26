package policies

import (
	"net/http"

	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/types"
	"github.com/kashguard/go-kms/internal/types/kms"
	"github.com/kashguard/go-kms/internal/util"
	"github.com/labstack/echo/v4"
)

func DeletePolicyRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.DELETE("/policies/:policyId", deletePolicyHandler(s))
}

func deletePolicyHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		params := kms.NewDeletePolicyRouteParams()
		if err := params.BindRequest(c.Request(), nil); err != nil {
			return err
		}

		// 检查策略是否存在
		_, err := s.MetadataStore.GetPolicy(ctx, params.PolicyID)
		if err != nil {
			log.Error().Err(err).Str("policy_id", params.PolicyID).Msg("Failed to get policy")
			if err.Error() == errPolicyNotFound {
				return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Policy not found")
			}
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to get policy")
		}

		// 删除策略
		if err := s.MetadataStore.DeletePolicy(ctx, params.PolicyID); err != nil {
			log.Error().Err(err).Str("policy_id", params.PolicyID).Msg("Failed to delete policy")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to delete policy")
		}

		return c.NoContent(http.StatusNoContent)
	}
}
