# CAELOMERE Portal Railway loader

This folder is the Railway deployment entry point for the Grok-built CAELOMERE portal and Library Visualisation.

Railway root directory: `/railway-portal`

Required file before deployment: `CAELOMERE-PORTAL-LITE.zip` in this folder.

Required Railway variables:
- DATABASE_URL
- BETTER_AUTH_SECRET
- BETTER_AUTH_URL
- VITE_AUTH_ENABLED=true
- VITE_GROK_OAUTH_ENABLED=false
- XAI_API_KEY (when live AI is enabled)

Health check: `/api/health`
Portal: `/app`
Login: `/login`
Library visualisation: `/lanterna`
