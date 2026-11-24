# Hardened Static OIDC Trust Policies (AWS, Azure, GCP)

resource "aws_iam_role" "github_actions_prod_deploy" {
  name = "github-prod-deploy"

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
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
            "token.actions.githubusercontent.com:sub" = "repo:acme-corp/payments:environment:production"
          }
        }
      }
    ]
  })
}

resource "azuread_application_federated_identity_credential" "github_prod" {
  application_id = "/applications/00000000-0000-0000-0000-000000000002"
  display_name   = "github-prod-env"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:acme-corp/payments:environment:production"
}

resource "google_iam_workload_identity_pool_provider" "github_restricted" {
  workload_identity_pool_id          = "github-pool"
  workload_identity_pool_provider_id = "github-provider"
  attribute_condition                = "assertion.repository == 'acme-corp/payments' && assertion.ref == 'refs/heads/main'"
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
