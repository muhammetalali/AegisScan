# syntax=docker/dockerfile:1.7
FROM node:22-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
# Production builds are lockfile-deterministic and tolerate bounded transient
# registry failures. The BuildKit cache preserves already downloaded packages
# across retry attempts without copying npm cache material into the image.
RUN --mount=type=cache,target=/root/.npm \
    set -eux; \
    npm_ci_with_retry() { \
        attempt=1; \
        while true; do \
            if npm ci \
                --no-audit \
                --no-fund \
                --fetch-retries=5 \
                --fetch-retry-factor=2 \
                --fetch-retry-mintimeout=10000 \
                --fetch-retry-maxtimeout=60000 \
                --fetch-timeout=120000; then \
                return 0; \
            fi; \
            if [ "$attempt" -ge 4 ]; then \
                echo "npm ci failed after $attempt attempts" >&2; \
                return 1; \
            fi; \
            sleep_seconds=$((attempt * 10)); \
            echo "retrying npm ci in ${sleep_seconds}s" >&2; \
            rm -rf node_modules; \
            sleep "$sleep_seconds"; \
            attempt=$((attempt + 1)); \
        done; \
    }; \
    npm_ci_with_retry

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
