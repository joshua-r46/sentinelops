package agentshield

default allow := false

allowed_actions := {
  "read_logs",
  "read_metrics",
  "read_config",
  "rollback_deployment",
  "restore_config",
  "restart_service",
  "set_resource_limit",
}

allowed_targets := {"api", "worker", "deployer", "redis", "postgres"}

allow if {
  input.action_type in allowed_actions
  input.target in allowed_targets
  input.risk != "R3"
}
