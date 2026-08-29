# Production TLS certificates

Do not commit private keys or certificates to Git.

Place the real production certificates on the deployment host as:

- `fullchain.pem`
- `privkey.pem`

Then start the production stack with:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

The base development compose file intentionally does not fabricate TLS certificates.
