terraform {
  required_version = ">= 1.7"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.31"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.14"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "kubernetes" {
  config_path = var.kubeconfig_path
}

provider "helm" {
  kubernetes {
    config_path = var.kubeconfig_path
  }
}

resource "kubernetes_namespace" "soc" {
  metadata {
    name = var.namespace
    labels = {
      # Pod Security Admission — durcissement natif au niveau du namespace.
      "pod-security.kubernetes.io/enforce" = "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "app.kubernetes.io/managed-by"       = "terraform"
    }
  }
}

# Secret HMAC généré par Terraform : jamais tapé par un humain, jamais en clair.
resource "random_password" "webhook_hmac" {
  length  = 48
  special = false
}

resource "kubernetes_secret" "integrations" {
  metadata {
    name      = "soc-autopilot-secrets"
    namespace = kubernetes_namespace.soc.metadata[0].name
  }
  data = {
    WEBHOOK_HMAC_SECRET = random_password.webhook_hmac.result
    WAZUH_API_USER      = var.wazuh_api_user
    WAZUH_API_PASSWORD  = var.wazuh_api_password
    THEHIVE_API_KEY     = var.thehive_api_key
    SLACK_BOT_TOKEN     = var.slack_bot_token
    VIRUSTOTAL_API_KEY  = var.virustotal_api_key
    DATABASE_URL        = var.database_url
  }
  type = "Opaque"
}

resource "kubernetes_config_map" "playbooks" {
  metadata {
    name      = "soc-autopilot-playbooks"
    namespace = kubernetes_namespace.soc.metadata[0].name
  }
  data = {
    for f in fileset("${path.module}/../playbooks", "*.yml") :
    f => file("${path.module}/../playbooks/${f}")
  }
}

resource "helm_release" "soc_autopilot" {
  name      = "soc-autopilot"
  chart     = "${path.module}/../charts/soc-autopilot"
  namespace = kubernetes_namespace.soc.metadata[0].name
  values    = [file("${path.module}/values.${var.environment}.yaml")]

  # La ConfigMap montée doit exister avant le pod (sinon CrashLoop).
  depends_on = [
    kubernetes_secret.integrations,
    kubernetes_config_map.playbooks,
  ]

  set {
    name  = "config.dryRun"
    value = var.dry_run
  }
}

output "webhook_hmac_secret" {
  value     = random_password.webhook_hmac.result
  sensitive = true
}
