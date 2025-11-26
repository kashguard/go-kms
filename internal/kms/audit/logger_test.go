// nolint:nonamedreturns,unparam // named returns are used for clarity; keyID is part of the interface signature
package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/kashguard/go-kms/internal/kms/audit"
	"github.com/kashguard/go-kms/internal/kms/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockMetadataStore 用于测试的 mock 存储
type mockAuditStore struct {
	events []*storage.AuditEvent
}

func (m *mockAuditStore) SaveAuditLog(_ context.Context, event *storage.AuditEvent) error {
	if m.events == nil {
		m.events = make([]*storage.AuditEvent, 0)
	}
	m.events = append(m.events, event)
	return nil
}

func (m *mockAuditStore) QueryAuditLogs(_ context.Context, filter *storage.AuditLogFilter) ([]*storage.AuditEvent, error) {
	events := make([]*storage.AuditEvent, 0)
	for _, event := range m.events {
		// 简单的过滤逻辑
		if filter != nil {
			if filter.KeyID != "" && event.KeyID != filter.KeyID {
				continue
			}
			if filter.EventType != "" && event.EventType != filter.EventType {
				continue
			}
		}
		events = append(events, event)
	}
	return events, nil
}

// 实现 storage.MetadataStore 接口的其他方法（仅用于测试）
func (m *mockAuditStore) SaveKeyMetadata(_ context.Context, _ *storage.KeyMetadata) error {
	return nil
}
func (m *mockAuditStore) GetKeyMetadata(_ context.Context, _ string) (*storage.KeyMetadata, error) {
	//nolint:nilnil // mock implementation returns nil for testing
	return nil, nil
}
func (m *mockAuditStore) UpdateKeyMetadata(_ context.Context, _ string, _ map[string]interface{}) error {
	return nil
}
func (m *mockAuditStore) DeleteKeyMetadata(_ context.Context, _ string) error {
	return nil
}
func (m *mockAuditStore) ListKeyMetadata(_ context.Context, _ *storage.KeyFilter) ([]*storage.KeyMetadata, error) {
	return nil, nil
}
func (m *mockAuditStore) SaveKeyVersion(_ context.Context, _ *storage.KeyVersion) error {
	return nil
}
func (m *mockAuditStore) GetKeyVersion(_ context.Context, _ string, _ int) (*storage.KeyVersion, error) {
	//nolint:nilnil // mock implementation returns nil for testing
	return nil, nil
}
func (m *mockAuditStore) GetPrimaryKeyVersion(_ context.Context, _ string) (*storage.KeyVersion, error) {
	//nolint:nilnil // mock implementation returns nil for testing
	return nil, nil
}
func (m *mockAuditStore) ListKeyVersions(_ context.Context, _ string) ([]*storage.KeyVersion, error) {
	return nil, nil
}
func (m *mockAuditStore) UpdateKeyVersionPrimary(_ context.Context, _ string, _ int, _ bool) error {
	return nil
}
func (m *mockAuditStore) SavePolicy(_ context.Context, _ *storage.Policy) error {
	return nil
}
func (m *mockAuditStore) GetPolicy(_ context.Context, policyID string) (*storage.Policy, error) {
	//nolint:nilnil // mock implementation returns nil for testing
	return nil, nil
}
func (m *mockAuditStore) ListPolicies(_ context.Context) ([]*storage.Policy, error) {
	//nolint:nilnil // mock implementation returns nil for testing
	return nil, nil
}
func (m *mockAuditStore) UpdatePolicy(_ context.Context, policyID string, policy *storage.Policy) error {
	return nil
}
func (m *mockAuditStore) DeletePolicy(_ context.Context, policyID string) error {
	return nil
}
func (m *mockAuditStore) SaveSecret(_ context.Context, _ *storage.Secret) error {
	return nil
}
func (m *mockAuditStore) GetSecret(_ context.Context, _ string) (*storage.Secret, error) {
	//nolint:nilnil // mock implementation returns nil for testing
	return nil, nil
}
func (m *mockAuditStore) UpdateSecret(_ context.Context, _ string, _ *storage.Secret) error {
	return nil
}
func (m *mockAuditStore) DeleteSecret(_ context.Context, _ string) error {
	return nil
}
func (m *mockAuditStore) SecretExists(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func TestAuditLogger_LogEvent(t *testing.T) {
	ctx := context.Background()
	mockStore := &mockAuditStore{
		events: make([]*storage.AuditEvent, 0),
	}
	logger := audit.NewLogger(mockStore)

	event := &audit.AuditEvent{
		EventType: "KeyCreated",
		KeyID:     "test-key-1",
		Operation: "create_key",
		Result:    "Success",
		Timestamp: time.Now(),
	}

	err := logger.LogEvent(ctx, event)
	require.NoError(t, err)
	assert.Len(t, mockStore.events, 1)
	assert.Equal(t, event.KeyID, mockStore.events[0].KeyID)
	assert.Equal(t, event.Operation, mockStore.events[0].Operation)
}

func TestAuditLogger_ListEvents(t *testing.T) {
	ctx := context.Background()
	mockStore := &mockAuditStore{
		events: make([]*storage.AuditEvent, 0),
	}
	logger := audit.NewLogger(mockStore)

	// 记录多个事件
	for i := 1; i <= 3; i++ {
		event := &audit.AuditEvent{
			EventType: "KeyCreated",
			KeyID:     "test-key-" + string(rune('0'+i)),
			Operation: "create_key",
			Result:    "Success",
			Timestamp: time.Now(),
		}
		err := logger.LogEvent(ctx, event)
		require.NoError(t, err)
	}

	// 注意：audit.Logger 接口只有 LogEvent 方法，没有 ListEvents 方法
	// 如果需要查询审计日志，应该直接使用 storage.MetadataStore.QueryAuditLogs
	events, err := mockStore.QueryAuditLogs(ctx, &storage.AuditLogFilter{
		Limit: 10,
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(events), 3)

	// 按 KeyID 过滤
	events, err = mockStore.QueryAuditLogs(ctx, &storage.AuditLogFilter{
		KeyID: "test-key-1",
		Limit: 10,
	})
	require.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, "test-key-1", events[0].KeyID)
}
