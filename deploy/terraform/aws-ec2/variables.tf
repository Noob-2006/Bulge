variable "region" {
  type    = string
  default = "us-east-1"
}
variable "vpc_id" { type = string }
variable "subnet_id" { type = string }
variable "instance_type" {
  type    = string
  default = "t3.medium"
}
variable "disk_gb" {
  type    = number
  default = 30
}
variable "egress_cidrs" {
  description = "Where seagent may connect on 443; narrow this to your proxy/model endpoints."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}
