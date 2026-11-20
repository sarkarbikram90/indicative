# Intentionally insecure Terraform configuration fixture for Trivy IaC testing
resource "aws_s3_bucket" "public_data" {
  bucket = "indicative-insecure-fixture-bucket"
}

resource "aws_s3_bucket_acl" "public_acl" {
  bucket = aws_s3_bucket.public_data.id
  acl    = "public-read"
}

resource "aws_security_group" "open_ssh" {
  name = "open-ssh-fixture"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
