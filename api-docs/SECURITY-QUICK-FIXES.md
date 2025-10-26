# Security Quick Fixes - Action Checklist

## 🚨 CRITICAL - Fix Immediately

### 1. PCRE2 Vulnerability in Nginx Containers
**CVE-2025-58050** - Heap buffer overflow

```bash
# Update base image in all nginx Dockerfiles
# Change FROM alpine:3.22 to latest or specify version with fix
# Then rebuild:

podman build -t localhost/timeherenow-nginx:latest -f nginx.Dockerfile .
podman build -t localhost/mintrootapi-nginx:latest -f /path/to/mintrootapi/nginx.Dockerfile .
podman build -t localhost/mintserverapi-nginx:latest -f /path/to/mintserverapi/nginx.Dockerfile .
podman build -t localhost/monitoring-nginx:latest -f /path/to/monitoring/nginx.Dockerfile .

# Restart affected containers
podman pod restart timeherenow-pod
podman pod restart monitoring-pod
```

### 2. Private Key Exposure
**CRITICAL** - Exposed asymmetric private key detected

```bash
# 1. Locate the exposed key
grep -r "BEGIN.*PRIVATE KEY" /path/to/source

# 2. Remove from source code/images

# 3. Use Podman secrets instead
podman secret create my-private-key /path/to/key.pem

# 4. Update container to use secret
# In your pod YAML or run command:
# --secret my-private-key,type=mount,target=/run/secrets/key.pem
```

---

## ⚠️ HIGH - Fix This Week

### 3. Node.js Dependency Vulnerabilities

```bash
# For mintrootapi-app
cd /path/to/mintrootapi
npm audit
npm update cross-spawn@7.0.5
npm update base-x@5.0.1
npm audit fix
npm test  # Verify nothing broke

# Rebuild image
podman build -t localhost/mintrootapi-app:latest -f api.Dockerfile .

# For mintserverapi-app
cd /path/to/mintserverapi
npm audit
npm update cross-spawn@7.0.5
npm update base-x@5.0.1
npm audit fix
npm test

# Rebuild image
podman build -t localhost/mintserverapi-app:latest -f api.Dockerfile .
```

### 4. Update Grafana

```bash
# Update Grafana to latest version
podman pull docker.io/grafana/grafana:latest

# Restart monitoring pod
podman pod restart monitoring-pod
```

---

## 📝 Verification Steps

### After Applying Fixes

```bash
# 1. Re-run security scan
./security-scan.sh

# 2. Verify containers are running
podman ps

# 3. Check logs for errors
podman logs timeherenow-container
podman logs timeherenow-nginx
podman logs monitoring-grafana

# 4. Test application endpoints
curl -k https://localhost:8443/health
curl -k https://localhost:3333/

# 5. Verify no secrets in images
podman run --rm localhost/timeherenow-image:latest sh -c "find / -name '*.pem' -o -name '*.key' 2>/dev/null"
```

---

## 🔄 Regular Maintenance Commands

```bash
# Weekly security scan
./security-scan.sh

# Check for npm vulnerabilities
cd /path/to/app && npm audit

# Update base images
podman pull alpine:3.22
podman pull node:20-alpine
podman pull nginx:mainline-alpine

# View container security status
podman inspect <container-id> --format '{{.Config.User}}'
podman inspect <container-id> --format '{{.HostConfig.Privileged}}'
```

---

## 📞 Need Help?

- **Full Report:** `container-security-report.md`
- **Summary:** `SECURITY-SUMMARY.md`
- **Trivy Docs:** https://trivy.dev/
- **CVE Details:** https://nvd.nist.gov/

---

**Last Updated:** October 26, 2025
