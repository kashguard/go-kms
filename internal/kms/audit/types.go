package audit

import "time"

// AuditEvent 审计事件
//
//nolint:revive // AuditEvent is the standard naming for audit events
type AuditEvent struct {
	Timestamp time.Time
	EventType string
	UserID    string
	KeyID     string
	Operation string
	Result    string
	Details   map[string]interface{}
	IPAddress string
}
