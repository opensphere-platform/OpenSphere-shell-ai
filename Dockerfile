FROM docker.io/library/node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm install --no-audit --no-fund
COPY angular.json tsconfig.json tsconfig.app.json ./
COPY src ./src
RUN npx ng build --configuration production

FROM docker.io/library/node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2
RUN apk upgrade --no-cache
WORKDIR /app
COPY server-runtime/package.json server-runtime/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
    && rm -f package.json package-lock.json \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
COPY --chmod=0644 server.js /app/server.js
COPY ui-shell/ /app/plugins/
COPY --from=build /app/dist/ai/browser /app/www
COPY kanidm-ca.crt /etc/kanidm-ca/ca.crt
ENV PLUGINS_DIR=/app/plugins \
    WWW_DIR=/app/www \
    PORT=8080 \
    NODE_EXTRA_CA_CERTS=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
    KANIDM_CA_PATH=/etc/kanidm-ca/ca.crt
EXPOSE 8080
USER 1000
CMD ["node", "/app/server.js"]
