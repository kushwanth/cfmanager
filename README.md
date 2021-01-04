# Cloudflare Manager

### cfmanager is an python script that helps to Manage CloudFlare zones using Cloudflare API
- read, create, delete DNS records
- shows zone details
- status of DNSSEC
- provides deails about zone settings
- shows in SSL certificates in zone
- shows analytics
- shows pagerules
- purges cache
- Account Logs

## Requirements:
- ``` pip install -r requirements.txt ```
- Cloudflare toke with write access to zone dns, purge cache and read access to analytics, dnssec, pagerules, settings, SSL certs
- For account logs you need account id, global api key and account email

## usage
After opening the script go to
- line 9 and add your token token there.
for account logs go to
- line 216 and add replace the account details with sameple name
(these auth keys and token will be hardcoded in to the script)

## you can modify the script according to your requirements

### This script is not officially endorsed by cloudflare