package policy

import (
	"context"

	"github.com/kashguard/go-kms/internal/kms/storage"
	"github.com/pkg/errors"
)

var (
	ErrPolicyNotFound = errors.New("policy not found")
	ErrPolicyDenied   = errors.New("policy denied")
)

// Engine 策略引擎接口
type Engine interface {
	EvaluatePolicy(ctx context.Context, policyID string, action string) error
	LoadPolicy(ctx context.Context, policyID string) (*Policy, error)
}

// engine 策略引擎实现
type engine struct {
	metadataStore storage.MetadataStore
}

// NewEngine 创建新的策略引擎
//
//nolint:ireturn // returning interface is intentional for abstraction
func NewEngine(metadataStore storage.MetadataStore) Engine {
	return &engine{
		metadataStore: metadataStore,
	}
}

// EvaluatePolicy 评估策略
func (e *engine) EvaluatePolicy(ctx context.Context, policyID string, action string) error {
	// 加载策略
	policy, err := e.LoadPolicy(ctx, policyID)
	if err != nil {
		return errors.Wrap(err, "failed to load policy")
	}

	// 评估策略
	allowed := false
	for _, statement := range policy.Statements {
		if statement.Effect == "Deny" {
			// 拒绝策略优先
			for _, deniedAction := range statement.Actions {
				if deniedAction == action || deniedAction == "*" {
					return ErrPolicyDenied
				}
			}
		} else if statement.Effect == "Allow" {
			// 检查是否允许
			for _, allowedAction := range statement.Actions {
				if allowedAction == action || allowedAction == "*" {
					allowed = true
					break
				}
			}
		}
	}

	if !allowed {
		return ErrPolicyDenied
	}

	return nil
}

// LoadPolicy 加载策略
func (e *engine) LoadPolicy(ctx context.Context, policyID string) (*Policy, error) {
	storagePolicy, err := e.metadataStore.GetPolicy(ctx, policyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get policy from storage")
	}

	// 解析策略文档
	// storagePolicy.PolicyDocument 已经是 map[string]interface{} 类型
	policyDoc := storagePolicy.PolicyDocument

	// 解析 statements
	statements := make([]*PolicyStatement, 0)
	//nolint:nestif // Policy parsing requires nested conditionals for type checking
	if statementsData, ok := policyDoc["statements"].([]interface{}); ok {
		for _, stmtData := range statementsData {
			if stmtMap, ok := stmtData.(map[string]interface{}); ok {
				stmt := &PolicyStatement{}
				if effect, ok := stmtMap["effect"].(string); ok {
					stmt.Effect = effect
				}
				if actions, ok := stmtMap["actions"].([]interface{}); ok {
					stmt.Actions = make([]string, 0, len(actions))
					for _, action := range actions {
						if actionStr, ok := action.(string); ok {
							stmt.Actions = append(stmt.Actions, actionStr)
						}
					}
				}
				if resources, ok := stmtMap["resources"].([]interface{}); ok {
					stmt.Resources = make([]string, 0, len(resources))
					for _, resource := range resources {
						if resourceStr, ok := resource.(string); ok {
							stmt.Resources = append(stmt.Resources, resourceStr)
						}
					}
				}
				if conditions, ok := stmtMap["conditions"].(map[string]interface{}); ok {
					stmt.Conditions = conditions
				}
				statements = append(statements, stmt)
			}
		}
	}

	return &Policy{
		PolicyID:    storagePolicy.PolicyID,
		Description: storagePolicy.Description,
		Statements:  statements,
	}, nil
}
