# Blob Cool tier after 7 days (no deletes)

Storage account: `<storage-account>` · container: `canary-logs`

Prefixes covered (whole container — OpenCanary dated archives, `current/`, and `cowrie/`):
- `YYYY/MM/DD/opencanary.log.gz` (OpenCanary rotated)
- `current/opencanary.log` and `current/cowrie-canary.log`
- `cowrie/YYYY/MM/DD/...`

## Apply (Mac, after az login)

```bash
az login
# Students subscription — pick the right one if prompted
az storage account management-policy create \
  --account-name <storage-account> \
  --policy '{
    "rules": [
      {
        "enabled": true,
        "name": "cool-after-7-days-all-archives",
        "type": "Lifecycle",
        "definition": {
          "filters": { "blobTypes": ["blockBlob"] },
          "actions": {
            "baseBlob": {
              "tierToCool": { "daysAfterModificationGreaterThan": 7 }
            }
          }
        }
      }
    ]
  }'
```

If a policy already exists, use `az storage account management-policy update` with the same JSON instead of create.

This only changes access tier to Cool after 7 days since last modification. It never deletes blobs.
