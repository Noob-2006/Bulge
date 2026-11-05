# Terraform: SE Agent on EC2 (Amazon Linux 2023)

    terraform init && terraform apply -var vpc_id=vpc-... -var subnet_id=subnet-...
    aws secretsmanager put-secret-value --secret-id "$(terraform output -raw api_key_secret_id)" --secret-string "$KEY"
    # (first boot waits for the secret: re-run `cloud-init clean --reboot` over SSM if you stored it late)

Reaching the host: SSM Session Manager (`terraform output ssm_command`); the instance has no public IP
and no inbound rule. Edit `../../cloud-init/seagent.yaml` for the package mirror, provider, model and policy.
Check without AWS credentials: `terraform init -backend=false && terraform validate`.
