# OpenSphere subShell: ai — standalone build.
#   Stage 1: build the Angular 22 app (Angular Element <osp-ai-shell>) → dist/ai/browser
#            (angular.json: @angular/build:application, outputHashing=none → predictable main.js + styles.css)
#   Stage 2: runtime feature-container — server.js serves the built bundle at /app/www + signed ui-shell at
#            /app/plugins + generic /api/k8s/* proxy + WS exec. ws is the only runtime dep (rest are node built-ins).
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm install --no-audit --no-fund
COPY angular.json tsconfig.json tsconfig.app.json ./
COPY src ./src
RUN npx ng build --configuration production

FROM node:22-alpine
WORKDIR /app
COPY --chmod=0644 server.js /app/server.js
COPY ui-shell/ /app/plugins/
COPY --from=build /app/dist/ai/browser /app/www
COPY --from=build /app/node_modules/ws /app/node_modules/ws
# Kanidm(콘솔 IdP) self-signed CA — 쓰기/exec 시 ES256 토큰 in-cluster JWKS(svc:8443) TLS 신뢰용.
COPY kanidm-ca.crt /etc/kanidm-ca/ca.crt
ENV PLUGINS_DIR=/app/plugins WWW_DIR=/app/www PORT=8080 \
    NODE_EXTRA_CA_CERTS=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
    KANIDM_CA_PATH=/etc/kanidm-ca/ca.crt
EXPOSE 8080
USER 1000
CMD ["node", "/app/server.js"]
