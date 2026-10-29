output "config_file" {
  description = "Path of the settings file the circuit writes on each host, which the packaged suricata.yaml includes."
  value       = local.config_file
}

output "rules_file" {
  description = "Path of the file holding custom_rules on each host."
  value       = local.rules_file
}

output "eve_log" {
  description = "Path of Suricata's EVE JSON log on each host, where alerts land."
  value       = local.eve_log
}
