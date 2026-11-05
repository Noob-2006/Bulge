# One EC2 instance running ark as a hardened system service, configured by cloud-init
# (../../cloud-init/ark.yaml). Intentionally small: no public IP, no inbound rules (ark talks
# out to the model API and chat platforms; operators use SSM Session Manager).
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.region
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023*-kernel-6.1-x86_64"]
  }
}

resource "aws_security_group" "ark" {
  name_prefix = "ark-"
  description = "ark agent: egress only"
  vpc_id      = var.vpc_id
  egress {
    description = "model API, package mirror, chat platforms"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.egress_cidrs
  }
}

resource "aws_secretsmanager_secret" "api_key" {
  name_prefix = "ark-model-api-key-"
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ark" {
  name_prefix        = "ark-"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.ark.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "read_key" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.api_key.arn]
  }
}

resource "aws_iam_role_policy" "read_key" {
  role   = aws_iam_role.ark.id
  policy = data.aws_iam_policy_document.read_key.json
}

resource "aws_iam_instance_profile" "ark" {
  name_prefix = "ark-"
  role        = aws_iam_role.ark.name
}

resource "aws_instance" "ark" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.ark.id]
  iam_instance_profile        = aws_iam_instance_profile.ark.name
  associate_public_ip_address = false
  metadata_options {
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1
  }
  root_block_device {
    encrypted   = true
    volume_size = var.disk_gb
  }
  # The cloud-init file fetches the key from Secrets Manager into /run/ark-api-key (0600) first.
  user_data = templatefile("${path.module}/user-data.tftpl", {
    ark_cloud_config = file("${path.module}/../../cloud-init/ark.yaml")
    secret_id        = aws_secretsmanager_secret.api_key.id
    region           = var.region
  })
  user_data_replace_on_change = true
  tags                        = { Name = "ark-agent" }
}
