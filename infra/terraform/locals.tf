locals {
  name = "${var.prefix}-${var.environment}"
  tags = {
    project     = "Jagadish-agent-auth-security"
    environment = var.environment
    company     = "northglass-fictional"
  }
}
