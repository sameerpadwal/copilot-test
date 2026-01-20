name: Deploy to Azure App Service
description: GitHub Actions workflow for deploying FastAPI app to Azure App Service

# =============================================================================
# SETUP INSTRUCTIONS
# =============================================================================
#
# 1. Create Azure App Service:
#    az group create --name myResourceGroup --location eastus
#    az appservice plan create --name myAppPlan --resource-group myResourceGroup --sku B1 --is-linux
#    az webapp create --resource-group myResourceGroup --plan myAppPlan --name taskapi-app --runtime "PYTHON:3.10"
#
# 2. Enable Docker Container:
#    az webapp config container set --name taskapi-app \
#      --resource-group myResourceGroup \
#      --docker-custom-image-name ghcr.io/yourusername/taskapi:latest \
#      --docker-registry-server-url https://ghcr.io \
#      --docker-registry-server-user yourusername \
#      --docker-registry-server-password <PAT>
#
# 3. Configure GitHub Secrets:
#    - AZURE_CREDENTIALS: Azure service principal JSON
#    - AZURE_APP_NAME: App Service name (e.g., taskapi-app)
#    - AZURE_RESOURCE_GROUP: Resource group name
#
# 4. Generate Azure Credentials:
#    az ad sp create-for-rbac --name "github-actions" \
#      --role contributor \
#      --scopes /subscriptions/{subscription-id}/resourceGroups/{resource-group} \
#      --json-auth
#
# =============================================================================

# Deployment strategy: Blue-Green using deployment slots
# Benefits:
# - Zero downtime deployment
# - Easy rollback
# - Staging environment for testing
# - Health checks before swap
