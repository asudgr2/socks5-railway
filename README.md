# Private SOCKS5 Proxy for Railway

Small, TCP-only SOCKS5 proxy with mandatory username/password authentication. It uses only Node.js built-in modules, runs as a non-root user, and exposes a minimal `GET /health` endpoint on the same Railway-assigned `PORT`.

## Architecture

One Node process accepts TCP connections on `PORT`. HTTP requests to `/health` receive a health response; all other connections must complete the SOCKS5 RFC 1928 greeting and RFC 1929 username/password exchange. Only the `CONNECT` command is supported. Each accepted connection creates a direct TCP stream to its requested destination; there is no HTTP proxy, UDP relay, DNS service, metrics endpoint, dashboard, or credential persistence.

Authentication is mandatory: the server selects only method `0x02` (username/password) and returns `0xff` when a client does not offer it. Failed authentications are tracked in memory by source IP; ten failures within one minute block further attempts from that IP for five minutes. Credentials are never included in logs.

## Environment variables

| Variable | Required | Description |
| --- | --- | --- |
| `PORT` | Yes | Listening port. Railway supplies this automatically. Local Docker users set it explicitly. |
| `SOCKS_USERNAME` | Yes | SOCKS5 username. |
| `SOCKS_PASSWORD` | Yes | SOCKS5 password; use a long random value. |
| `ALLOWED_IPS` | No | Comma-separated IPv4 addresses or CIDRs permitted to connect, such as `203.0.113.8,198.51.100.0/24`. Empty permits all source IPs **but authentication is still required**. |
| `LOG_LEVEL` | No | `debug`, `info` (default), `warn`, or `error`. |

Copy `.env.example` for local configuration. Never commit your real `.env` file.

## Deploy to Railway

1. Create a new Railway project from this repository; Railway detects the included `Dockerfile`.
2. In the Railway service variables, set `SOCKS_USERNAME` and `SOCKS_PASSWORD`. Railway creates `PORT`; do not override it.
3. Optionally set `ALLOWED_IPS` to your current public IP or CIDR. A home IP can change, so update this variable when needed.
4. Deploy. Railway calls `GET /health` using the service `PORT`; the service restarts on failure according to `railway.json`.
5. In **Service Settings → Networking → TCP Proxy**, create a TCP Proxy targeting the Railway-assigned application `PORT`. Railway generates a TCP proxy domain and external port; use that exact `domain:port` in SOCKS clients. Do not use the normal HTTPS public domain for SOCKS traffic.

Railway TCP Proxy assigns the external hostname and port, and incoming traffic may be distributed across replicas. A Railway proxy is suitable for personal use and moderate traffic, but it is not a replacement for a fixed-IP VPS: outbound IPs, connection limits, bandwidth, and long-lived connection behavior depend on Railway's current infrastructure and plan. Check your Railway networking configuration before relying on a fixed egress IP or a long-running browser session.

## Local run

Docker is the recommended local path:

```sh
docker build -t private-socks5 .
docker run --rm -p 1080:1080 --env-file .env private-socks5
```

Or, with Node.js 20+:

```sh
set -a; . ./.env; set +a
node src/server.js
```

Windows PowerShell alternative:

```powershell
$env:PORT='1080'; $env:SOCKS_USERNAME='user'; $env:SOCKS_PASSWORD='a-long-secret'; node src/server.js
```

## Client examples

Replace `proxy.example.com:1080`, `user`, and `secret` with your endpoint and credentials. URL-encode special characters in credentials used within a proxy URL.

```python
# requests needs: pip install 'requests[socks]'
import requests
proxy = 'socks5h://user:secret@proxy.example.com:1080'
print(requests.get('https://api.ipify.org?format=json', proxies={'http': proxy, 'https': proxy}, timeout=20).json())
```

```python
# httpx needs: pip install 'httpx[socks]'
import httpx
with httpx.Client(proxy='socks5://user:secret@proxy.example.com:1080', timeout=20) as client:
    print(client.get('https://api.ipify.org?format=json').json())
```

```python
# Selenium Chrome (SOCKS5 auth support depends on Chrome/driver policy; proxy auth extension may be required.)
from selenium import webdriver
options = webdriver.ChromeOptions()
options.add_argument('--proxy-server=socks5://proxy.example.com:1080')
driver = webdriver.Chrome(options=options)
# Supply SOCKS credentials through your organization's approved browser-auth mechanism.
```

```javascript
// Playwright: Chromium proxy credentials are passed explicitly.
const { chromium } = require('playwright');
const browser = await chromium.launch({
  proxy: { server: 'socks5://proxy.example.com:1080', username: 'user', password: 'secret' }
});
```

```sh
curl --proxy socks5h://user:secret@proxy.example.com:1080 https://api.ipify.org
```

## Verification

```sh
# Health / reachability (HTTP health endpoint, not via SOCKS)
curl -fsS http://127.0.0.1:1080/health

# Authentication and egress IP. A JSON response means the SOCKS handshake worked.
curl --proxy socks5h://user:secret@127.0.0.1:1080 https://api.ipify.org?format=json

# Incorrect credentials must fail.
curl --proxy socks5h://user:wrong@127.0.0.1:1080 https://api.ipify.org -v

# Compare direct and proxied external IP. They should differ when proxy egress differs.
curl https://api.ipify.org; echo
curl --proxy socks5h://user:secret@127.0.0.1:1080 https://api.ipify.org; echo

# End-to-end connection latency (run several times; inspect time_connect).
curl -o /dev/null -sS -w 'connect=%{time_connect}s total=%{time_total}s\n' \
  --proxy socks5h://user:secret@127.0.0.1:1080 https://example.com

# 50 concurrent authenticated requests (requires GNU xargs).
seq 50 | xargs -n1 -P10 -I{} curl -fsS --proxy socks5h://user:secret@127.0.0.1:1080 https://example.com -o /dev/null
```

## Security and operations

- Keep `SOCKS_PASSWORD` unique, random, and secret. Rotate it in Railway if it is exposed.
- Set `ALLOWED_IPS` when your PC has a stable public IPv4 address; it provides an additional perimeter control but does not replace authentication.
- A managed TCP proxy can change or obscure the source address seen by the container. Confirm `ALLOWED_IPS` behavior with a rejected/accepted local test after deployment; never rely on it as the sole access control.
- The container runs as the unprivileged `node` user and contains no package manager install step or additional services.
- Logs are JSON and record connection metadata only. Destination hostnames and source addresses can be sensitive operational data; set `LOG_LEVEL=warn` if you do not need successful-connection logs.
- The proxy intentionally supports TCP `CONNECT` only. UDP ASSOCIATE, BIND, unauthenticated SOCKS, and HTTP proxying are rejected/not implemented.
- Graceful shutdown first stops accepting new connections, then gives active streams up to ten seconds to finish.

## Troubleshooting

- **Railway health check fails:** confirm `PORT` is not set to a fixed value and inspect deployment logs for a missing credential variable.
- **Connection immediately closes:** verify your current public IP matches `ALLOWED_IPS`, including CIDR and VPN changes.
- **Authentication fails:** confirm the client uses SOCKS5 credentials, not HTTP proxy auth, and URL-encode special characters in proxy URLs.
- **Browser cannot authenticate:** some Chrome/Selenium setups do not expose SOCKS authentication in command-line proxy settings. Use Playwright's `proxy` credentials or an approved browser authentication extension/policy.
- **External IP does not differ:** local tests naturally use your local network; deploy to Railway and compare direct vs. proxied egress, noting Railway egress behavior can vary.
