# A Record Scanning for Subdomain Takeover
This script pairs with my Cactus Con 12 talk on Subdomain Takeovers. This script can be used as-is to check if A-Records in your Cloudflare instance point to resources in Azure that the organization doesn't own anymore. You just need a few things to get started!

## Getting Started
### Azure
In order to pull all public IP addresses from Azure, you'll need to create an App in the Azure App Registration portal. Work with your cloud team to make sure that app has permissions in all of the subscritions that might contain public IP Addresses. Once you have this completed, you can grab the Application (client) ID and the Directory (tenant) ID from the Overiew page. Then, in Certificates & Secrets, you can create a Client Secret. Set the following environment variables:
```
AZURE_TENANT_ID
AZURE_CLIENT_ID
AZURE_CLIENT_SECRET
```
You can use whatever method you prefer to set those environment variables, this repository has an `.env_template` file you could use to start with.

### Cloudflare
In your Cloudflare portal, navigate to My Profile > API Tokens to create a token for this application. The token needs Zone.DNS Read permissions in all zones. Set the following environment variable equal to that value:
```
CLOUDFLARE_TOKEN
```

## Run The Script
```
python3 a-record-scan.py
```
