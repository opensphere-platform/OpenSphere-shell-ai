FROM node:22-bookworm-slim

WORKDIR /app
COPY package.json server.js ./

ENV PORT=18080 \
    OSP_GPU_BRIDGE_BIND=0.0.0.0 \
    OSP_GPU_BRIDGE_MAX_CONCURRENCY=1 \
    OSP_GPU_BRIDGE_PROVIDER=docker-gpu \
    OSP_GPU_BRIDGE_DATA_DIR=/data

RUN mkdir -p /data && chown -R node:node /data /app
USER node

EXPOSE 18080
CMD ["node", "/app/server.js"]
