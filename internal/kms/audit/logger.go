package audit

import (
	"context"
	"time"

	"github.com/kashguard/go-kms/internal/kms/storage"
	"github.com/pkg/errors"
)

// Logger 审计日志接口
type Logger interface {
	LogEvent(ctx context.Context, event *AuditEvent) error
}

// logger 审计日志实现
type logger struct {
	metadataStore storage.MetadataStore
}

// NewLogger 创建新的审计日志
//
//nolint:ireturn // returning interface is intentional for abstraction
func NewLogger(metadataStore storage.MetadataStore) Logger {
	return &logger{
		metadataStore: metadataStore,
	}
}

// LogEvent 记录审计事件
func (l *logger) LogEvent(ctx context.Context, event *AuditEvent) error {
	// 设置时间戳（如果未设置）
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	storageEvent := &storage.AuditEvent{
		Timestamp: event.Timestamp,
		EventType: event.EventType,
		UserID:    event.UserID,
		KeyID:     event.KeyID,
		Operation: event.Operation,
		Result:    event.Result,
		Details:   event.Details,
		IPAddress: event.IPAddress,
	}

	if err := l.metadataStore.SaveAuditLog(ctx, storageEvent); err != nil {
		return errors.Wrap(err, "failed to save audit log")
	}

	return nil
}
