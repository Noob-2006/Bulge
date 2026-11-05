output "instance_id" {
  value = aws_instance.seagent.id
}
output "api_key_secret_id" {
  description = "Store the model key here (aws secretsmanager put-secret-value); it is never in Terraform state as plaintext."
  value       = aws_secretsmanager_secret.api_key.id
}
output "ssm_command" {
  value = "aws ssm start-session --target ${aws_instance.seagent.id}"
}
