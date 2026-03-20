# ---------- build stage ----------
FROM node:20-alpine AS build

# build-base provides gcc/g++/make for better-sqlite3 native addon
RUN apk add --no-cache build-base python3

WORKDIR /app

# Copy dependency manifests first for layer caching
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/
COPY packages/server/package.json packages/server/
COPY packages/cli/package.json packages/cli/

RUN npm ci

# Copy source and build
COPY tsconfig.json tsconfig.base.json ./
COPY packages/ packages/

RUN npm run build

# Prune dev dependencies after build
RUN npm prune --omit=dev

# ---------- runtime stage ----------
FROM node:20-alpine

# better-sqlite3 needs libstdc++ at runtime
RUN apk add --no-cache libstdc++ \
    && addgroup -S vana && adduser -S vana -G vana

WORKDIR /app

# Copy built output and production node_modules from build stage
COPY --from=build --chown=vana:vana /app/package.json /app/package-lock.json ./
COPY --from=build --chown=vana:vana /app/node_modules/ node_modules/

# Each workspace package needs package.json, dist/, and any hoisted node_modules
COPY --from=build --chown=vana:vana /app/packages/core/package.json packages/core/package.json
COPY --from=build --chown=vana:vana /app/packages/core/dist/ packages/core/dist/
COPY --from=build --chown=vana:vana /app/packages/core/node_modules/ packages/core/node_modules/

COPY --from=build --chown=vana:vana /app/packages/server/package.json packages/server/package.json
COPY --from=build --chown=vana:vana /app/packages/server/dist/ packages/server/dist/

# Data directory for SQLite DB, keys, logs
RUN mkdir -p /data && chown vana:vana /data

# Cloud-mode defaults (can be overridden at runtime)
# SERVER_ORIGIN MUST be provided at runtime for cloud deployments
# (e.g. -e SERVER_ORIGIN=https://ps.example.com)
ENV PERSONAL_SERVER_ROOT_PATH=/data \
    TUNNEL_ENABLED=false \
    DEV_UI_ENABLED=false

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8080/health', (r) => {if(r.statusCode!==200)process.exit(1)})"

USER vana

CMD ["node", "packages/server/dist/index.js"]
