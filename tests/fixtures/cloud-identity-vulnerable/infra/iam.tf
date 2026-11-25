resource "aws_iam_role" "acme_ecommerce_deploy" {
  name = "acme-ecommerce-deploy"

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
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:acme/*"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "admin_attach" {
  role       = aws_iam_role.acme_ecommerce_deploy.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role_policy" "broad_deploy_policy" {
  name = "broad-deploy-policy"
  role = aws_iam_role.acme_ecommerce_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "kms:Decrypt"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["iam:PutRolePolicy", "sts:AssumeRole"]
        Resource = "*"
      }
    ]
  })
}
