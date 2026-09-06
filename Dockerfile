# ---------- build stage ----------
FROM node:22-alpine AS build

# build-base provides gcc/g++/make for better-sqlite3 native addon
RUN apk add --no-cache build-base python3

WORKDIR /app

# Copy dependency manifests first for layer caching
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/
COPY packages/lite/package.json packages/lite/
COPY packages/server/package.json packages/server/
COPY packages/cli/package.json packages/cli/
COPY packages/enclave/package.json packages/enclave/

RUN npm ci

# Copy source and build
COPY tsconfig.base.json ./
COPY packages/ packages/

# Build only the workspaces needed by the server image. The root build also
# compiles repo-local scripts that are intentionally absent from this image.
RUN npm run build --workspace @opendatalabs/personal-server-ts-core \
  && npm run build --workspace @opendatalabs/personal-server-ts-lite \
  && npm run build --workspace @opendatalabs/personal-server-ts-server

# Install only the packages deliberately kept external to the bundle. Skip
# lifecycle scripts, then reuse the better-sqlite3 addon built by npm ci.
RUN mkdir -p /runtime-deps \
  && cp packages/server/bundle-runtime/package.json \
    packages/server/bundle-runtime/package-lock.json /runtime-deps/ \
  && cd /runtime-deps \
  && npm ci --omit=dev --ignore-scripts \
    --no-audit --no-fund --prefer-offline \
  && cp -R /app/node_modules/better-sqlite3/build \
    /runtime-deps/node_modules/better-sqlite3/build

# ---------- runtime stage ----------
FROM node:22-alpine

# better-sqlite3 needs libstdc++ at runtime
RUN apk add --no-cache libstdc++ \
    && addgroup -S vana && adduser -S vana -G vana

WORKDIR /app

# Ship the bundle, its disk-resolved assets, and only external runtime packages.
COPY --from=build --chown=vana:vana /runtime-deps/node_modules/ node_modules/
COPY --from=build --chown=vana:vana /app/packages/server/dist/package.json packages/server/dist/package.json
COPY --from=build --chown=vana:vana /app/packages/server/dist/bundle/ packages/server/dist/bundle/
COPY --from=build --chown=vana:vana /app/packages/server/dist/ui/ packages/server/dist/ui/

# Preserve the established non-enclave invocation while resolving import.meta
# from the bundle's real path. The image's default CMD uses the bundle directly.
RUN ln -s bundle/enclave-main.mjs packages/server/dist/index.js

# Data directory for SQLite DB, keys, logs
RUN mkdir -p /data && chown vana:vana /data

# Cloud-mode defaults (can be overridden at runtime)
# SERVER_ORIGIN MUST be provided at runtime for cloud deployments
# (e.g. -e SERVER_ORIGIN=https://ps.example.com)
ENV CLOUD_MODE=true \
    PERSONAL_SERVER_ROOT_PATH=/data \
    TUNNEL_ENABLED=false \
    DEV_UI_ENABLED=false

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8080/health', (r) => {if(r.statusCode!==200)process.exit(1)})"

USER vana

# If /data is mounted as a volume with wrong ownership, the GCE startup script
# handles this (runs as root before docker run). For local dev, run with:
#   docker run --user root -e ... vana/personal-server
# or pre-chown the host directory.
CMD ["node", "packages/server/dist/bundle/enclave-main.mjs"]
