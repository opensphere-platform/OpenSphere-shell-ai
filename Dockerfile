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
COPY kanidm-ca.crt /etc/kanidm-ca/ca.crt
ENV PLUGINS_DIR=/app/plugins \
    WWW_DIR=/app/www \
    PORT=8080 \
    NODE_EXTRA_CA_CERTS=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
    KANIDM_CA_PATH=/etc/kanidm-ca/ca.crt
EXPOSE 8080
USER 1000
CMD ["node", "/app/server.js"]
