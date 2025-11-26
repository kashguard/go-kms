package audit

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/kashguard/go-kms/internal/api"
	"github.com/kashguard/go-kms/internal/api/httperrors"
	"github.com/kashguard/go-kms/internal/kms/storage"
	"github.com/kashguard/go-kms/internal/types"
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

		// 构建过滤器
		filter := &storage.AuditLogFilter{
			Limit:  100, //nolint:mnd // default limit for audit logs
			Offset: 0,
		}

		// 解析查询参数（直接使用 Echo 的 QueryParam）
		if keyID := c.QueryParam("key_id"); keyID != "" {
			filter.KeyID = keyID
		}
		if userID := c.QueryParam("user_id"); userID != "" {
			filter.UserID = userID
		}
		if eventType := c.QueryParam("event_type"); eventType != "" {
			filter.EventType = eventType
		}
		if operation := c.QueryParam("operation"); operation != "" {
			filter.Operation = operation
		}
		if result := c.QueryParam("result"); result != "" {
			filter.Result = result
		}

		// 解析时间参数
		if startTimeStr := c.QueryParam("start_time"); startTimeStr != "" {
			if startTime, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
				filter.StartTime = &startTime
			}
		}
		if endTimeStr := c.QueryParam("end_time"); endTimeStr != "" {
			if endTime, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
				filter.EndTime = &endTime
			}
		}

		// 解析 limit 和 offset
		if limitStr := c.QueryParam("limit"); limitStr != "" {
			if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
				filter.Limit = limit
			}
		}
		if offsetStr := c.QueryParam("offset"); offsetStr != "" {
			if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
				filter.Offset = offset
			}
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
