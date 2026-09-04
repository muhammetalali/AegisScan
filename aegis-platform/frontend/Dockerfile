FROM node:22-alpine AS build
WORKDIR /app

COPY package*.json ./
# Use the manifest as the source of truth while the lockfile is regenerated
# by npm. This keeps Docker builds valid when frontend tooling is added.
RUN npm install --no-audit --no-fund

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
