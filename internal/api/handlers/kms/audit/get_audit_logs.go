package audit

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

func GetAuditLogsRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1KMS.GET("/audit-logs", getAuditLogsHandler(s))
}

func getAuditLogsHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		params := kms.NewGetAuditLogsRouteParams()
		if err := params.BindRequest(c.Request(), nil); err != nil {
			return err
		}

		// 构建过滤器
		filter := &storage.AuditLogFilter{
			Limit:  100, //nolint:mnd // default limit for audit logs
			Offset: 0,
		}

		// 解析查询参数
		if params.KeyID != nil {
			filter.KeyID = *params.KeyID
		}
		if params.UserID != nil {
			filter.UserID = *params.UserID
		}
		if params.EventType != nil {
			filter.EventType = *params.EventType
		}
		if params.Operation != nil {
			filter.Operation = *params.Operation
		}
		if params.Result != nil {
			filter.Result = *params.Result
		}

		// 解析时间参数
		if params.StartTime != nil {
			startTime := time.Time(*params.StartTime)
			filter.StartTime = &startTime
		}
		if params.EndTime != nil {
			endTime := time.Time(*params.EndTime)
			filter.EndTime = &endTime
		}

		// 解析 limit 和 offset
		if params.Limit != nil {
			filter.Limit = int(*params.Limit)
		}
		if params.Offset != nil {
			filter.Offset = int(*params.Offset)
		}

		// 查询审计日志
		events, err := s.MetadataStore.QueryAuditLogs(ctx, filter)
		if err != nil {
			log.Error().Err(err).Msg("Failed to query audit logs")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to query audit logs")
		}

		// 转换响应
		eventResponses := make([]*types.GetAuditLogsResponseEventsItems0, 0, len(events))
		for _, event := range events {
			timestamp := strfmt.DateTime(event.Timestamp)
			eventResponse := &types.GetAuditLogsResponseEventsItems0{
				Timestamp: &timestamp,
				EventType: &event.EventType,
				Operation: &event.Operation,
				Result:    &event.Result,
				UserID:    event.UserID,
				KeyID:     event.KeyID,
				IPAddress: event.IPAddress,
			}
			if event.Details != nil {
				eventResponse.Details = event.Details
			}
			eventResponses = append(eventResponses, eventResponse)
		}

		response := &types.GetAuditLogsResponse{
			Events: eventResponses,
			Total:  int64(len(eventResponses)),
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
