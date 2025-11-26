package audit

import (
	"github.com/kashguard/go-kms/internal/auth"
	"github.com/kashguard/go-kms/internal/kms/audit"
	"github.com/labstack/echo/v4"
)

// BuildAuditEvent 从 Echo context 构建审计事件，自动填充 user_id 和 ip_address
func BuildAuditEvent(c echo.Context, eventType, keyID, operation, result string, details map[string]interface{}) *audit.AuditEvent {
	ctx := c.Request().Context()

	// 获取用户 ID
	userID := ""
	if user := auth.UserFromContext(ctx); user != nil {
		userID = user.ID
	}

	// 获取 IP 地址
	ipAddress := c.RealIP()
	if ipAddress == "" {
		ipAddress = c.Request().RemoteAddr
	}

	return &audit.AuditEvent{
		EventType: eventType,
		UserID:    userID,
		KeyID:     keyID,
		Operation: operation,
		Result:    result,
		Details:   details,
		IPAddress: ipAddress,
	}
}
