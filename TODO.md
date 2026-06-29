# TODO — Privacy-First PII Redactor

This file lists known gaps, manual tasks, and future improvements to address after the initial build.
Items are grouped by priority and category.

---

## 🔴 High Priority (Before Production Use)

### Security
- [ ] **Replace `httpx` with `httpx2`** in the project dependencies once httpx2 is stable — the current starlette TestClient deprecation warning points to this.
- [ ] **Tighten CORS origins** in `api/app.py`. The current default is `allow_origins=["*"]`. In production, this must be set to only trusted origins.
- [ ] **Rate limiting** — no rate limiting is currently applied. Add a `slowapi` or similar middleware to protect the API from abuse.
- [ ] **Validate Redis TLS settings** — if `REDIS_URL` uses `rediss://` (TLS), ensure the certificate chain is validated. Add a CI test for this.

### Authentication
- [ ] **Rotate API key support** — the current implementation supports a single static key. Consider adding key rotation or short-lived tokens for production.
- [ ] **Apply auth to all sensitive endpoints** — currently only `/v1/restore` and `/v1/chat/completions` enforce auth. Decide whether `/v1/redact` should also require auth.

### Observability
- [ ] **Add structured logging** using `structlog` or `python-json-logger` for machine-parseable logs in production.
- [ ] **Add metrics endpoint** (Prometheus `/metrics`) for latency, entity counts, and request rates.
- [ ] **Add OpenTelemetry tracing** for distributed request tracing across the proxy.

---

## 🟡 Medium Priority (Quality of Life)

### Detection Accuracy
- [ ] **Download spaCy model in CI** — tests currently run with `ENABLE_SPACY=false`. Add a CI job that downloads `en_core_web_sm` and runs the full pipeline.
- [ ] **Add multilingual spaCy models** — currently only `en_core_web_sm` is tried. Add support for `xx_ent_wiki_sm` (multilingual) or other language-specific models.
- [ ] **Improve address detection** — the current regex catches simple patterns but misses complex multi-line addresses. Consider using Presidio's address recognizer once ML is enabled.
- [ ] **Add NIF/NIT/DNI patterns** — Spanish and Latin American national ID numbers are not covered by the current regex set.
- [ ] **Add CPF/CNPJ patterns** — Brazilian tax IDs (common in LATAM applications) are not detected.
- [ ] **Add PAN (India) patterns** — `[A-Z]{5}[0-9]{4}[A-Z]` pattern for Indian Permanent Account Numbers.
- [ ] **Add PESEL (Poland)** — Polish national identification number.

### API & Proxy
- [ ] **Streaming LLM responses** — the current proxy buffers the full response before restoring. Add support for Server-Sent Events (SSE) streaming for lower latency.
- [ ] **Anthropic-native format support** — the proxy currently only handles OpenAI-compatible format. Add native Anthropic API support.
- [ ] **Google Gemini API support** — add a Gemini provider to `proxy/`.
- [ ] **Multi-turn conversation redaction** — in chat mode, maintain a single combined mapping across all turns in a conversation session.
- [ ] **Batch redaction endpoint** — `POST /v1/redact/batch` for redacting multiple texts in one request.

### Configuration
- [ ] **Per-entity confidence thresholds** in YAML config are loaded but not applied by the `PIIDetector` orchestrator. Wire up `entity_overrides.min_confidence` to the detector pipeline.
- [ ] **Hot-reload config** — allow YAML config changes to take effect without a full restart.

---

## 🟢 Lower Priority (Future Enhancements)

### Deployment
- [ ] **Kubernetes Helm chart** — add a `deploy/helm/` chart for K8s deployments.
- [ ] **Health check improvements** — the current `/health` endpoint is a simple liveness probe. Add `/readiness` that checks Redis connectivity and detector initialization.
- [ ] **Multi-stage Docker build** — the current Dockerfile is single-stage. A multi-stage build would reduce image size significantly (remove dev dependencies and build artifacts).
- [ ] **ARM64 Docker image** — add `linux/arm64` to the Docker build matrix for Apple Silicon / Graviton deployments.

### Performance
- [ ] **Async detection pipeline** — Presidio and spaCy detection are currently synchronous (blocking). Move them to a thread pool executor for better async performance under load.
- [ ] **LRU cache for regex compilation** — patterns are compiled once at startup, but consider benchmarking pattern matching on very large texts.
- [ ] **Connection pooling for Redis** — verify the Redis client uses connection pooling properly under load.

### Open-Source Readiness
- [ ] **PyPI publication** — set up GitHub Actions to publish to PyPI on tagged releases. Update `pyproject.toml` with the correct `project.urls`.
- [ ] **Add `CHANGELOG.md`** — document notable changes for each release.
- [ ] **Add integration tests** — a separate `tests/integration/` suite that spins up a real Redis instance and tests the full stack.
- [ ] **Add benchmark tests** — measure P50/P95 latency for a 1KB prompt with different detector combinations.
- [ ] **Add a demo** — a hosted demo or short video showing the tool in action.

### Documentation
- [ ] **Replace placeholder GitHub org** — update `README.md` and `SECURITY.md` to use the real GitHub org/repo URL once published.
- [ ] **API usage cookbook** — add a `docs/` directory with worked examples (Node.js, Python, curl).
- [ ] **Compliance notes** — add a `docs/compliance.md` summarising GDPR Article 4 definitions and where this tool fits.

---

## ✅ Completed

- [x] Core regex detection (email, phone, credit card, IBAN, IP, URL, SSN, DOB, address, ZIP)
- [x] Luhn algorithm for credit card validation
- [x] Presidio integration (optional, graceful fallback)
- [x] spaCy integration (optional, graceful fallback)
- [x] Conflict resolution (regex > presidio > spacy priority)
- [x] Placeholder deduplication within a single request
- [x] In-memory mapping store with TTL
- [x] Redis mapping store with TTL
- [x] FastAPI REST API (detect, redact, restore, chat proxy)
- [x] API key authentication (constant-time comparison)
- [x] Request size limit middleware
- [x] CLI (redact, redact-file, detect, serve)
- [x] Custom recognizers via Python dict and YAML
- [x] Docker + Docker Compose deployment
- [x] 220 automated tests
- [x] README, LICENSE, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT
- [x] GitHub Actions CI workflow
