# Azure App Service Configuration

## Step 1: Create Azure Resources

### Using Azure CLI:
```bash
# Login to Azure
az login

# Create resource group
az group create \
  --name myResourceGroup \
  --location eastus

# Create App Service Plan (Linux, B1 for development, P1V2 for production)
az appservice plan create \
  --name myAppServicePlan \
  --resource-group myResourceGroup \
  --sku B1 \
  --is-linux

# Create Web App
az webapp create \
  --resource-group myResourceGroup \
  --plan myAppServicePlan \
  --name taskapi-prod \
  --runtime "PYTHON:3.10"

# Enable deployment slots (staging and production)
az webapp deployment slot create \
  --resource-group myResourceGroup \
  --name taskapi-prod \
  --slot staging
```

## Step 2: Configure Docker Registry Access

```bash
# Create container registry (optional)
az acr create \
  --resource-group myResourceGroup \
  --name taskapi \
  --sku Basic

# Get credentials for GitHub Actions
az acr credential show \
  --name taskapi \
  --resource-group myResourceGroup
```

## Step 3: Create Azure Service Principal for GitHub Actions

```bash
# Get your subscription ID
SUBSCRIPTION_ID=$(az account show --query id -o tsv)

# Create service principal with appropriate role
az ad sp create-for-rbac \
  --name "github-actions-taskapi" \
  --role contributor \
  --scopes /subscriptions/$SUBSCRIPTION_ID/resourceGroups/myResourceGroup \
  --json-auth > azure-credentials.json

# The output will look like:
# {
#   "clientId": "...",
#   "clientSecret": "...",
#   "subscriptionId": "...",
#   "tenantId": "..."
# }

# Copy the entire JSON output to GitHub Secrets as AZURE_CREDENTIALS
```

## Step 4: Configure GitHub Secrets

Go to GitHub repository → Settings → Secrets and variables → Actions

Add the following secrets:
- **AZURE_CREDENTIALS**: JSON from service principal (full content from azure-credentials.json)
- **AZURE_APP_NAME**: taskapi-prod
- **AZURE_RESOURCE_GROUP**: myResourceGroup

## Step 5: Configure Environment Variables

Add environment variables in Azure App Service:

### Via Azure Portal:
Settings → Configuration → Application settings

Key-value pairs:
```
SECRET_KEY: <strong-secret-key-from-secrets-manager>
ENVIRONMENT: production
ALLOWED_ORIGINS: https://yourdomain.com,https://app.yourdomain.com
ALLOWED_HOSTS: yourdomain.com,api.yourdomain.com
WEBSITES_PORT: 8000
```

### Via Azure CLI:
```bash
az webapp config appsettings set \
  --resource-group myResourceGroup \
  --name taskapi-prod \
  --settings \
    SECRET_KEY="$(openssl rand -hex 32)" \
    ENVIRONMENT="production" \
    ALLOWED_ORIGINS="https://yourdomain.com" \
    ALLOWED_HOSTS="yourdomain.com" \
    WEBSITES_PORT=8000
```

## Step 6: Configure Docker Settings

### Via Azure CLI:
```bash
az webapp config container set \
  --name taskapi-prod \
  --resource-group myResourceGroup \
  --docker-custom-image-name ghcr.io/yourusername/taskapi-app:latest \
  --docker-registry-server-url https://ghcr.io \
  --docker-registry-server-user <github-username> \
  --docker-registry-server-password <github-pat>
```

## Step 7: Configure Continuous Deployment

Option 1: Use GitHub Actions (Recommended - this workflow)
- Automatic deployment on push to main
- Automated testing
- Blue-green deployment with slots

Option 2: Use Azure's Built-in Deployment
```bash
# Enable continuous deployment from container registry
az webapp deployment container config \
  --name taskapi-prod \
  --resource-group myResourceGroup \
  --enable-cd true
```

## Step 8: Monitor and Logging

### Enable Application Insights:
```bash
# Create Application Insights instance
az monitor app-insights component create \
  --app taskapi-insights \
  --location eastus \
  --resource-group myResourceGroup

# Connect to App Service
az webapp config appsettings set \
  --resource-group myResourceGroup \
  --name taskapi-prod \
  --settings APPINSIGHTS_INSTRUMENTATIONKEY="<instrumentation-key>"
```

### View Logs:
```bash
# Stream logs in real-time
az webapp log tail \
  --resource-group myResourceGroup \
  --name taskapi-prod

# Or use Azure Portal:
# App Service → App Service logs → Stream logs
```

## Step 9: Testing Deployment

```bash
# Check deployment status
az webapp deployment list \
  --resource-group myResourceGroup \
  --name taskapi-prod

# Test application
curl https://taskapi-prod.azurewebsites.net/

# Test with authentication
curl -X POST https://taskapi-prod.azurewebsites.net/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"TestPassword123!"}'
```

## Step 10: Setup Custom Domain (Optional)

```bash
# Add custom domain
az webapp config hostname add \
  --resource-group myResourceGroup \
  --webapp-name taskapi-prod \
  --hostname api.yourdomain.com

# Create SSL certificate
az appservice plan create \
  --name appservice-cert \
  --resource-group myResourceGroup

# Note: Use Azure App Service Managed Certificate or external SSL
```

## Deployment Workflow

1. **Push to main branch** → Triggers GitHub Actions
2. **Test stage**: Runs pytest, linting, coverage
3. **Build stage**: Builds Docker image, pushes to GHCR
4. **Deploy stage**:
   - Deploy to staging slot
   - Run health checks
   - Swap staging → production
5. **Monitor**: Check logs and metrics
6. **Rollback** (if needed): Swap back to previous version

## Troubleshooting

### Application won't start
```bash
# Check logs
az webapp log tail --resource-group myResourceGroup --name taskapi-prod

# Verify environment variables
az webapp config appsettings list \
  --resource-group myResourceGroup \
  --name taskapi-prod
```

### Container not pulling
```bash
# Verify credentials
az webapp config container show \
  --resource-group myResourceGroup \
  --name taskapi-prod

# Restart app
az webapp restart \
  --resource-group myResourceGroup \
  --name taskapi-prod
```

### Deployment stuck
```bash
# Clear deployment history
az webapp deployment slot delete \
  --resource-group myResourceGroup \
  --name taskapi-prod \
  --slot staging

# Recreate slot
az webapp deployment slot create \
  --resource-group myResourceGroup \
  --name taskapi-prod \
  --slot staging
```

## Scaling

### Vertical Scaling (Change SKU):
```bash
az appservice plan update \
  --name myAppServicePlan \
  --resource-group myResourceGroup \
  --sku P1V2
```

### Horizontal Scaling (Auto-scale):
```bash
az monitor autoscale create \
  --resource-group myResourceGroup \
  --resource myAppServicePlan \
  --resource-type "Microsoft.Web/serverfarms" \
  --name autoscale-taskapi \
  --min-count 2 \
  --max-count 10 \
  --count 2
```

## Cost Optimization

- **Development**: Use B1 tier (~$7/month)
- **Production**: Use P1V2 tier (~$30/month) with autoscale
- **Database**: Use PostgreSQL Single Server Flexible tier
- **Monitoring**: Use Log Analytics with 30-day retention

## Security Checklist

- ✅ HTTPS/TLS enforced
- ✅ Environment variables for secrets
- ✅ Service principal with minimal permissions
- ✅ Deployment slots for safe rollback
- ✅ Health checks configured
- ✅ Application Insights enabled
- ✅ Audit logging enabled
- ✅ IP restrictions configured (if needed)

## Next Steps

1. Configure monitoring alerts
2. Setup backup strategy
3. Configure auto-healing
4. Setup custom metrics
5. Plan disaster recovery
6. Document runbooks for incidents
