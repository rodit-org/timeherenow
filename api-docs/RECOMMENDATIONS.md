# 12-Factor and Production-Readiness Recommendations (Prioritized)

- **Externalize timers and split a worker process (enables HA and scale)**
  - Move in-memory timers + disk persistence to a durable scheduler/queue (e.g., Redis, SQS + EventBridge Scheduler, Cloud Tasks).
  - Run a separate worker process/service for webhook delivery; keep the API stateless.

- **Adopt immutable, reproducible image-based releases**
  - Build Docker images in CI using `npm ci` with `package-lock.json` and push to a registry (GHCR/ECR/ACR/GCR).
  - Deploy by pulling a versioned tag; stop building on the target host via rsync.

- **Add readiness/liveness endpoints and health-gated rollouts**
  - Implement `GET /live` (process alive) and `GET /ready` (NEAR cache initialized, auth client OK).
  - Use readiness probes to gate traffic during deploys and enable zero-downtime rollouts.

- **Enable distributed rate limiting**
  - Turn on IP and user rate limits in production; back them with a distributed store (e.g., Redis) for multi-replica correctness.
  - Keep SDK-driven per-user limits but ensure shared state across instances.

- **Unify logging to stdout and expand observability**
  - Emit Nginx access/error logs to stdout; keep app logs structured JSON; optional Loki sink.
  - Add tracing (OpenTelemetry SDK) and Prometheus metrics (`prom-client`) for golden signals.

- **Introduce CI quality gates (tests, lint, security scans)**
  - Add Jest/Vitest unit and minimal integration tests; run in GitHub Actions and block deploy on failures.
  - Add ESLint/Prettier; run `npm audit` and container scans (Trivy/Grype) in CI.

- **Harden Dockerfile and runtime**
  - Use multi-stage builds; `COPY package*.json` then `npm ci --omit=dev`; keep non-root user and `tini`.
  - Pin base images and consider periodic rebuilds; set `LOG_LEVEL=info` (or `warn`/`error`) for production.

- **Improve gateway (Nginx) and performance defaults**
  - Enable gzip/brotli for JSON; tune proxy buffers/timeouts for expected payloads.
  - Parameterize allowed CORS origins via env; minimize file writes by logging to stdout.

- **Clarify configuration and permission-map lifecycle**
  - Keep `METHOD_PERMISSION_MAP` generation in CI; avoid committing environment-specific changes in `config/default.json`.
  - Optionally support runtime generation on boot behind a feature flag.

- **Dev/prod parity via containers**
  - Provide a docker-compose for local dev (API + Nginx [+ optional Loki]); sample `.env.example`.
  - Mirror prod ports, probes, and envs locally.

- **Security improvements**
  - Avoid logging sensitive request bodies/headers at info level in `signclient` path; prefer structured minimal logs.
  - Store secrets in Vault/Secret Manager; automate TLS cert renewals outside containers.

- **Documentation and runbooks**
  - Add: local dev quickstart (compose), operational runbook (health probes, rollbacks, log locations), and SLOs for timers/endpoints.

- **Cloud provider deployment patterns (pick one first)**
  - Cloud Run: set `SERVERPORT=$PORT`, use Secret Manager, Cloud Tasks for timers, deploy from Actions via `gcloud`.
  - AWS ECS Fargate: ECR + ALB, Secrets Manager/SSM, SQS/EventBridge for timers; blue/green deploy.
  - Azure Container Apps: ACR, Key Vault, App Insights; Storage Queues or Durable Functions for timers.

- **Performance and scalability**
  - Consider Node clustering or multiple replicas behind the proxy (once state is externalized).
  - Add basic load tests; review keep-alive/headers timeouts and memory limits under load.
