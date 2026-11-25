resource "aws_iam_role" "acme_ecommerce_scoped_deploy" {
  name                 = "acme-ecommerce-scoped-deploy"
  permissions_boundary = "arn:aws:iam::123456789012:policy/indicative-ci-boundary"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRoleWithWebIdentity"
        Principal = {
          Federated = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
        }
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
            "token.actions.githubusercontent.com:sub" = "repo:acme/ecommerce:environment:production"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "scoped_deploy_policy" {
  name = "scoped-deploy-policy"
  role = aws_iam_role.acme_ecommerce_scoped_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "arn:aws:s3:::acme-ecommerce-prod-assets/*"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = "arn:aws:secretsmanager:us-east-1:123456789012:secret:ecommerce-prod/config-*"
      },
      {
        Effect    = "Deny"
        NotAction = ["s3:PutObject", "s3:GetObject", "secretsmanager:GetSecretValue"]
        Resource  = "*"
      }
    ]
  })
}
