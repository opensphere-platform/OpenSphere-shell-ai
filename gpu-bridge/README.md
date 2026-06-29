# OpenSphere GPU Bridge MVP

This directory contains the Phase 1 containerized External GPU Compute Backend for OpenSphere AI Hub.

The bridge is intentionally small:

- Runs as a Docker container.
- Uses Docker `--gpus all` to access the host GPU.
- Exposes the OAH External Compute Backend MVP API.
- Accepts only allowlisted `jobType` values. Arbitrary commands are not accepted.
- Supports `smoke` jobs backed by `nvidia-smi`.

## Build

```powershell
docker build -t localhost:5000/opensphere-gpu-bridge:v0.1.0 .
```

## Run

```powershell
docker run --rm -d `
  --name opensphere-gpu-bridge `
  --gpus all `
  -p 18080:18080 `
  -e OSP_GPU_BRIDGE_TOKEN=dev-token `
  localhost:5000/opensphere-gpu-bridge:v0.1.0
```

From OpenSphere AI Hub running inside Docker Desktop Kubernetes, use:

```text
http://host.docker.internal:18080
```

## API

Public:

```http
GET /health
```

Bearer token required:

```http
GET /capabilities
POST /jobs
GET /jobs/{jobId}
GET /jobs/{jobId}/logs
POST /jobs/{jobId}/cancel
```

Submit a smoke job:

```powershell
curl.exe -s `
  -H "Authorization: Bearer dev-token" `
  -H "Content-Type: application/json" `
  -d "{\"jobType\":\"smoke\"}" `
  http://localhost:18080/jobs
```

## OAH Fields

| OAH field | Value |
| --- | --- |
| Usage option | External GPU endpoint |
| External endpoint | `http://host.docker.internal:18080` |
| Credential Secret | `oah-external-gpu-credentials` |
| Resource name | `external.opensphere.io/gpu` |
| Max concurrency | `1` |

Kubernetes Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: oah-external-gpu-credentials
  namespace: opensphere-system
type: Opaque
stringData:
  token: dev-token
```
