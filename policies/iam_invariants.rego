package enterprise.iam

default allow = false

# Rule: Deny statements that allow wildcard actions on any resource
deny[msg] {
    statement := input.Statement[_]
    statement.Effect == "Allow"
    is_wildcard(statement.Action)
    msg := sprintf("[CRITICAL-IAM-01] Statement '%v' grants wildcard action ('*'). Least-privilege violation.", [statement.Sid])
}

# Rule: Deny unconstrained iam:PassRole with wildcard Resource
deny[msg] {
    statement := input.Statement[_]
    statement.Effect == "Allow"
    action_contains_pass_role(statement.Action)
    statement.Resource == "*"
    msg := sprintf("[CRITICAL-IAM-02] Statement '%v' allows unconstrained 'iam:PassRole' with Resource='*'. Escalation boundary violation.", [statement.Sid])
}

# Helper: check for wildcard action
is_wildcard(action) {
    action == "*"
}
is_wildcard(action) {
    is_array(action)
    action[_] == "*"
}

# Helper: check for iam:PassRole action
action_contains_pass_role(action) {
    action == "iam:PassRole"
}
action_contains_pass_role(action) {
    is_array(action)
    action[_] == "iam:PassRole"
}
