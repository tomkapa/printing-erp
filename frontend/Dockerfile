# Frontend image for the printing-erp SPA (React + Vite, built with Bun).
# Build context is this `frontend/` directory:
#   docker build -t printing-erp-frontend frontend/
#
# The image is a pure static server. API routing (which prefixes go to the
# backend) is decided by the Ingress, not baked in here, so the same image runs
# unchanged across every environment.

# ---- builder ----------------------------------------------------------------
FROM oven/bun:1 AS builder
WORKDIR /build

# Install dependencies first (cached unless the lockfile changes), then build.
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile
COPY . .
# `bun run build` == `tsc && vite build` → ./dist (see package.json).
RUN bun run build

# ---- runtime ----------------------------------------------------------------
# Unprivileged nginx: runs as a non-root user (uid 101) and listens on 8080, so
# no root and no privileged-port bind. The server block also listens on 8080.
FROM nginxinc/nginx-unprivileged:1.27-alpine AS runtime
COPY --from=builder /build/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
