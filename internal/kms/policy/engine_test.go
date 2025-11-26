// nolint:nonamedreturns,unparam // named returns are used for clarity; keyID is part of the interface signature
package policy_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kashguard/go-kms/internal/kms/policy"
	"github.com/kashguard/go-kms/internal/kms/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockMetadataStore 用于测试的 mock 存储
type mockMetadataStore struct {
	policies map[string]*storage.Policy
}

// 实现 storage.MetadataStore 接口的所有方法（仅实现策略相关方法）
func (m *mockMetadataStore) SaveKeyMetadata(_ context.Context, _ *storage.KeyMetadata) error {
	return nil
}
func (m *mockMetadataStore) GetKeyMetadata(_ context.Context, _ string) (*storage.KeyMetadata, error) {
	//nolint:nilnil // mock implementation returns nil for testing
	return nil, nil
}
func (m *mockMetadataStore) UpdateKeyMetadata(_ context.Context, _ string, _ map[string]interface{}) error {
	return nil
}
func (m *mockMetadataStore) DeleteKeyMetadata(_ context.Context, _ string) error {
	return nil
}
func (m *mockMetadataStore) ListKeyMetadata(_ context.Context, _ *storage.KeyFilter) ([]*storage.KeyMetadata, error) {
	return nil, nil
}
func (m *mockMetadataStore) SaveKeyVersion(_ context.Context, _ *storage.KeyVersion) error {
	return nil
}
func (m *mockMetadataStore) GetKeyVersion(_ context.Context, _ string, _ int) (*storage.KeyVersion, error) {
	//nolint:nilnil // mock implementation returns nil for testing
	return nil, nil
}
func (m *mockMetadataStore) GetPrimaryKeyVersion(_ context.Context, _ string) (*storage.KeyVersion, error) {
	//nolint:nilnil // mock implementation returns nil for testing
	return nil, nil
}
func (m *mockMetadataStore) ListKeyVersions(_ context.Context, _ string) ([]*storage.KeyVersion, error) {
	return nil, nil
}
func (m *mockMetadataStore) UpdateKeyVersionPrimary(_ context.Context, _ string, _ int, _ bool) error {
	return nil
}
func (m *mockMetadataStore) SaveAuditLog(_ context.Context, _ *storage.AuditEvent) error {
	return nil
}
func (m *mockMetadataStore) QueryAuditLogs(_ context.Context, _ *storage.AuditLogFilter) ([]*storage.AuditEvent, error) {
	return nil, nil
}

func (m *mockMetadataStore) GetPolicy(_ context.Context, policyID string) (*storage.Policy, error) {
	if p, ok := m.policies[policyID]; ok {
		return p, nil
	}
	return nil, errors.New("policy not found")
}

func (m *mockMetadataStore) SavePolicy(_ context.Context, policy *storage.Policy) error {
	if m.policies == nil {
		m.policies = make(map[string]*storage.Policy)
	}
	m.policies[policy.PolicyID] = policy
	return nil
}

func (m *mockMetadataStore) ListPolicies(_ context.Context) ([]*storage.Policy, error) {
	policies := make([]*storage.Policy, 0, len(m.policies))
	for _, p := range m.policies {
		policies = append(policies, p)
	}
	return policies, nil
}

func (m *mockMetadataStore) UpdatePolicy(_ context.Context, policyID string, policy *storage.Policy) error {
	if _, ok := m.policies[policyID]; !ok {
		return errors.New("policy not found")
	}
	m.policies[policyID] = policy
	return nil
}

func (m *mockMetadataStore) DeletePolicy(_ context.Context, policyID string) error {
	if _, ok := m.policies[policyID]; !ok {
		return errors.New("policy not found")
	}
	delete(m.policies, policyID)
	return nil
}
func (m *mockMetadataStore) SaveSecret(ctx context.Context, secret *storage.Secret) error {
	return nil
}
func (m *mockMetadataStore) GetSecret(ctx context.Context, keyID string) (*storage.Secret, error) {
	//nolint:nilnil // mock implementation returns nil for testing
	return nil, nil
}

// nolint:nonamedreturns,unparam // named returns are used for clarity; keyID is part of the interface signature
func (m *mockMetadataStore) UpdateSecret(ctx context.Context, keyID string, secret *storage.Secret) error {
	return nil
}

// nolint:nonamedreturns,unparam // named returns are used for clarity; keyID is part of the interface signature
func (m *mockMetadataStore) DeleteSecret(ctx context.Context, keyID string) error {
	return nil
}

// nolint:nonamedreturns,unparam // named returns are used for clarity; keyID is part of the interface signature
func (m *mockMetadataStore) SecretExists(ctx context.Context, keyID string) (bool, error) {
	return false, nil
}

func TestPolicyEngine_EvaluatePolicy(t *testing.T) {
	ctx := context.Background()
	mockStore := &mockMetadataStore{
		policies: make(map[string]*storage.Policy),
	}
	engine := policy.NewEngine(mockStore)

	// 创建允许策略
	policyDoc := map[string]interface{}{
		"statements": []interface{}{
			map[string]interface{}{
				"effect":  "Allow",
				"actions": []interface{}{"create_key", "encrypt"},
			},
		},
	}

	policyData := &storage.Policy{
		PolicyID:       "test-policy-1",
		PolicyDocument: policyDoc,
	}
	err := mockStore.SavePolicy(ctx, policyData)
	require.NoError(t, err)

	// 测试允许的操作
	err = engine.EvaluatePolicy(ctx, "test-policy-1", "create_key")
	require.NoError(t, err, "create_key should be allowed")

	err = engine.EvaluatePolicy(ctx, "test-policy-1", "encrypt")
	require.NoError(t, err, "encrypt should be allowed")

	// 测试未授权的操作（策略中没有明确允许，应该被拒绝）
	err = engine.EvaluatePolicy(ctx, "test-policy-1", "delete_key")
	require.Error(t, err, "delete_key should be denied (not in allowed actions)")
	assert.Contains(t, err.Error(), "denied", "error should contain 'denied'")
}

func TestPolicyEngine_DenyPolicy(t *testing.T) {
	ctx := context.Background()
	mockStore := &mockMetadataStore{
		policies: make(map[string]*storage.Policy),
	}
	engine := policy.NewEngine(mockStore)

	// 创建拒绝策略
	policyDoc := map[string]interface{}{
		"statements": []map[string]interface{}{
			{
				"effect":  "Deny",
				"actions": []string{"delete_key"},
			},
		},
	}

	policyData := &storage.Policy{
		PolicyID:       "test-policy-deny",
		PolicyDocument: policyDoc,
	}
	err := mockStore.SavePolicy(ctx, policyData)
	require.NoError(t, err)

	// 测试拒绝的操作
	err = engine.EvaluatePolicy(ctx, "test-policy-deny", "delete_key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "denied")
}
