# printing-erp Helm chart

A generic, environment-agnostic chart for [printing-erp](https://github.com/tomkapa/printing-erp):
the axum API backend and the React/Vite SPA frontend. It ships **no environment
config and no secrets** — only safe placeholders. You supply real values at deploy
time.

## What it deploys

- **backend** Deployment + Service (`:8080`). Runs DB migrations on startup, so a
  generous `startupProbe` guards first boot; `readinessProbe` hits `/health/ready`
  (DB + Redis). Runs as non-root with a read-only root filesystem.
- **frontend** Deployment + Service (`:80`) — nginx serving the static SPA.
- **Ingress** with a path split: `/api` (the business API) and `/health` (probes)
  go to the backend; everything else (the SPA shell and its bundled assets) goes
  to the frontend.
- Optional **ephemeral Redis** (`redis.enabled`) for PR previews.
- Optional **bootstrap Job** (`bootstrap.enabled`) that creates the `erp_app` role
  for self-hosters.

It never deploys Postgres — bring your own (`postgres.external` is a reminder).

## Configuration: secret vs non-secret

The backend reads everything from `APP__*` env vars (see `backend/src/config.rs`).
The chart splits them:

- **Non-secret** → `config` (rendered into a ConfigMap), e.g. `APP__STORAGE__REGION`,
  `APP__STORAGE__BUCKET`, `APP__TELEMETRY__SERVICE_NAME`.
- **Secret** → an External Secrets store (`externalSecret.enabled`) or a Secret you
  manage (`existingSecret`). Keys must be named exactly as the env vars:
  `APP__DATABASE__URL`, `APP__DATABASE__ADMIN_URL`, `APP__REDIS__URL`,
  `APP__STORAGE__ACCESS_KEY_ID`, `APP__STORAGE__SECRET_ACCESS_KEY`,
  `APP__AUTH__JWT_SECRET` (≥ 256 bits).

## Recommended use: ArgoCD multi-source (private values)

Because the app repo is public, keep this chart here and your real values in a
**private** repo, combined at sync time. Sketch:

```yaml
sources:
  - repoURL: https://github.com/tomkapa/printing-erp
    path: deploy/chart
    targetRevision: <tag>
    helm:
      valueFiles:
        - $values/printing-erp/values-prod.yaml
  - repoURL: https://github.com/<you>/<private-infra>   # provides $values
    targetRevision: main
    ref: values
```

## Self-host quick start

```bash
helm install erp deploy/chart \
  --set existingSecret=erp-secrets \
  --set ingress.enabled=true --set ingress.host=erp.example.com \
  --set-string config.APP__STORAGE__REGION=auto \
  --set-string config.APP__STORAGE__BUCKET=erp-assets
```

You provide `erp-secrets` (a Secret with the keys above) and a reachable Postgres
and Redis. Set `bootstrap.enabled=true` to have the chart create the `erp_app`
role for you.
