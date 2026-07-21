variable "kubeconfig_path" {
  type    = string
  default = "~/.kube/config"
}

variable "namespace" {
  type    = string
  default = "soc-autopilot"
}

variable "environment" {
  type    = string
  default = "lab"
}

variable "dry_run" {
  type    = bool
  default = true
}

variable "wazuh_api_user" {
  type    = string
  default = "wazuh"
}

variable "wazuh_api_password" {
  type      = string
  sensitive = true
}

variable "thehive_api_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "slack_bot_token" {
  type      = string
  sensitive = true
  default   = ""
}

variable "virustotal_api_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "database_url" {
  type      = string
  sensitive = true
}
