# Deliberately Vulnerable Static OIDC Trust Policies (AWS, Azure, GCP)

resource "aws_iam_role" "github_actions_broad_deploy" {
  name = "github-actions-broad-deploy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:acme-corp/*"
          }
        }
      }
    ]
  })
}

resource "azuread_application_federated_identity_credential" "github_broad" {
  application_id = "/applications/00000000-0000-0000-0000-000000000001"
  display_name   = "github-broad-trust"
  audiences      = ["*"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:acme-corp/payments:*"
}

resource "google_iam_workload_identity_pool_provider" "github_unrestricted" {
  workload_identity_pool_id          = "github-pool"
  workload_identity_pool_provider_id = "github-provider"
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
