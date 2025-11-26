package policy

// PolicyStatement 策略声明
//
//nolint:revive // PolicyStatement is the standard naming for policy statements
type PolicyStatement struct {
	Effect     string                 // Allow 或 Deny
	Actions    []string               // 操作列表（create_key, read_key, update_key, delete_key, use_key, rotate_key）
	Resources  []string               // 资源列表（keys/*, keys/{key_id}）
	Conditions map[string]interface{} // 条件
}

// Policy 策略定义
type Policy struct {
	PolicyID    string
	Description string
	Statements  []*PolicyStatement
}
