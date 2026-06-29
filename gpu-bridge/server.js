import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';

const PORT = Number(process.env.PORT || 18080);
const BIND = process.env.OSP_GPU_BRIDGE_BIND || '0.0.0.0';
const TOKEN = process.env.OSP_GPU_BRIDGE_TOKEN || 'dev-token';
const MAX_CONCURRENCY = Math.max(1, Number(process.env.OSP_GPU_BRIDGE_MAX_CONCURRENCY || 1) || 1);
const PROVIDER = process.env.OSP_GPU_BRIDGE_PROVIDER || 'docker-gpu';
const DATA_DIR = process.env.OSP_GPU_BRIDGE_DATA_DIR || '/data';
const SERVICE_STARTED_AT = new Date().toISOString();

const jobs = new Map();
const runningJobs = new Set();

function json(res, status, body) {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(payload);
}

function notFound(res) {
  json(res, 404, { error: 'NotFound', message: 'Endpoint not found.' });
}

function unauthorized(res) {
  json(res, 401, { error: 'Unauthorized', message: 'Bearer token is required.' });
}

function methodNotAllowed(res) {
  json(res, 405, { error: 'MethodNotAllowed', message: 'Method is not allowed for this endpoint.' });
}

function isAuthorized(req) {
  const header = req.headers.authorization || '';
  return header === `Bearer ${TOKEN}`;
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (!chunks.length) return {};
  const text = Buffer.concat(chunks).toString('utf8');
  if (!text.trim()) return {};
  return JSON.parse(text);
}

function runProcess(command, args, options = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd: options.cwd || DATA_DIR,
      env: { ...process.env, ...(options.env || {}) },
      shell: false,
      windowsHide: true,
    });
    const logs = [];
    const startedAt = new Date().toISOString();
    let timeoutHandle = null;
    let timedOut = false;

    const push = (source, chunk) => {
      String(chunk || '')
        .split(/\r?\n/)
        .filter(Boolean)
        .forEach((line) => logs.push({ time: new Date().toISOString(), source, line }));
    };

    child.stdout.on('data', (chunk) => push('stdout', chunk));
    child.stderr.on('data', (chunk) => push('stderr', chunk));
    child.on('error', (error) => push('error', error.message));

    if (options.timeoutSeconds) {
      timeoutHandle = setTimeout(() => {
        timedOut = true;
        child.kill('SIGTERM');
      }, options.timeoutSeconds * 1000);
    }

    child.on('close', (code, signal) => {
      if (timeoutHandle) clearTimeout(timeoutHandle);
      resolve({
        command,
        args,
        code,
        signal,
        timedOut,
        logs,
        startedAt,
        finishedAt: new Date().toISOString(),
      });
    });
  });
}

async function nvidiaSmi(args) {
  return runProcess('nvidia-smi', args, { timeoutSeconds: 30 });
}

function parseGpuCsv(text) {
  return String(text || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [index, name, driverVersion, memoryTotalMiB, memoryUsedMiB, utilizationGpuPercent, temperatureC] = line.split(',').map((part) => part.trim());
      return {
        id: index,
        name,
        vendor: name?.toLowerCase().includes('nvidia') ? 'nvidia' : 'unknown',
        driverVersion,
        memoryTotalMiB: Number(memoryTotalMiB),
        memoryUsedMiB: Number(memoryUsedMiB),
        utilizationGpuPercent: Number(utilizationGpuPercent),
        temperatureC: Number(temperatureC),
        cudaAvailable: true,
      };
    });
}

async function gpuCapabilities() {
  const result = await nvidiaSmi([
    '--query-gpu=index,name,driver_version,memory.total,memory.used,utilization.gpu,temperature.gpu',
    '--format=csv,noheader,nounits',
  ]);
  const output = result.logs.map((item) => item.line).join('\n');
  const gpus = result.code === 0 ? parseGpuCsv(output) : [];
  return {
    backendType: 'opensphere-gpu-bridge',
    provider: PROVIDER,
    version: '0.1.0',
    generatedAt: new Date().toISOString(),
    ready: gpus.length > 0,
    gpus,
    supportedJobTypes: ['smoke'],
    maxConcurrency: MAX_CONCURRENCY,
    currentConcurrency: runningJobs.size,
    artifactStores: ['local'],
    limits: {
      maxRuntimeSeconds: 300,
      maxLogBytes: 1048576,
    },
    diagnostics: result.code === 0 ? [] : [{
      phase: 'NvidiaSmiFailed',
      message: output || `nvidia-smi exited with code ${result.code}`,
    }],
  };
}

function jobResponse(job) {
  return {
    jobId: job.jobId,
    jobType: job.jobType,
    phase: job.phase,
    createdAt: job.createdAt,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    exitCode: job.exitCode,
    signal: job.signal,
    timedOut: job.timedOut,
    requestId: job.requestId,
    metadata: job.metadata,
    summary: job.summary,
  };
}

function appendLog(job, source, line) {
  job.logs.push({ time: new Date().toISOString(), source, line });
}

async function runSmokeJob(job) {
  runningJobs.add(job.jobId);
  job.phase = 'Running';
  job.startedAt = new Date().toISOString();
  appendLog(job, 'system', 'Starting OpenSphere GPU smoke job.');
  const result = await nvidiaSmi([]);
  job.logs.push(...result.logs);
  job.finishedAt = result.finishedAt;
  job.exitCode = result.code;
  job.signal = result.signal;
  job.timedOut = result.timedOut;
  job.phase = result.code === 0 && !result.timedOut ? 'Succeeded' : 'Failed';
  job.summary = result.code === 0 ? 'nvidia-smi completed successfully.' : 'nvidia-smi failed.';
  runningJobs.delete(job.jobId);
}

async function createJob(req, res) {
  if (!isAuthorized(req)) return unauthorized(res);
  if (runningJobs.size >= MAX_CONCURRENCY) {
    return json(res, 429, {
      error: 'ConcurrencyLimitExceeded',
      message: `GPU bridge is already running ${runningJobs.size}/${MAX_CONCURRENCY} job(s).`,
    });
  }

  let body;
  try {
    body = await readJson(req);
  } catch {
    return json(res, 400, { error: 'InvalidJson', message: 'Request body must be valid JSON.' });
  }

  const jobType = String(body.jobType || '').trim();
  if (jobType !== 'smoke') {
    return json(res, 400, {
      error: 'UnsupportedJobType',
      message: 'MVP bridge only supports jobType "smoke". Arbitrary commands are not accepted.',
      supportedJobTypes: ['smoke'],
    });
  }

  const jobId = `job-${new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14)}-${randomUUID().slice(0, 8)}`;
  const job = {
    jobId,
    jobType,
    phase: 'Queued',
    createdAt: new Date().toISOString(),
    requestId: req.headers['x-opensphere-request-id'] || randomUUID(),
    metadata: body.metadata || {},
    logs: [],
    summary: 'Queued for execution.',
  };
  jobs.set(jobId, job);
  void runSmokeJob(job);
  return json(res, 202, jobResponse(job));
}

function getJob(res, jobId) {
  const job = jobs.get(jobId);
  if (!job) return json(res, 404, { error: 'JobNotFound', message: `Job ${jobId} was not found.` });
  return json(res, 200, jobResponse(job));
}

function getJobLogs(res, jobId, url) {
  const job = jobs.get(jobId);
  if (!job) return json(res, 404, { error: 'JobNotFound', message: `Job ${jobId} was not found.` });
  const tail = Math.max(1, Math.min(1000, Number(url.searchParams.get('tail') || 200) || 200));
  return json(res, 200, {
    jobId,
    lines: job.logs.slice(-tail),
    truncated: job.logs.length > tail,
  });
}

function cancelJob(res, jobId) {
  const job = jobs.get(jobId);
  if (!job) return json(res, 404, { error: 'JobNotFound', message: `Job ${jobId} was not found.` });
  if (!['Queued', 'Running'].includes(job.phase)) return json(res, 200, jobResponse(job));
  job.phase = 'Cancelling';
  job.summary = 'Cancel requested. The smoke MVP job may already be complete.';
  appendLog(job, 'system', 'Cancel requested.');
  return json(res, 202, jobResponse(job));
}

async function handle(req, res) {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  if (req.method === 'GET' && url.pathname === '/health') {
    return json(res, 200, {
      status: 'ok',
      service: 'opensphere-gpu-bridge',
      provider: PROVIDER,
      version: '0.1.0',
      startedAt: SERVICE_STARTED_AT,
      time: new Date().toISOString(),
    });
  }

  if (url.pathname !== '/health' && !isAuthorized(req)) return unauthorized(res);

  if (req.method === 'GET' && url.pathname === '/capabilities') {
    return json(res, 200, await gpuCapabilities());
  }
  if (req.method === 'POST' && url.pathname === '/jobs') return createJob(req, res);

  const jobLogsMatch = url.pathname.match(/^\/jobs\/([^/]+)\/logs$/);
  if (jobLogsMatch && req.method === 'GET') return getJobLogs(res, jobLogsMatch[1], url);

  const jobCancelMatch = url.pathname.match(/^\/jobs\/([^/]+)\/cancel$/);
  if (jobCancelMatch && req.method === 'POST') return cancelJob(res, jobCancelMatch[1]);

  const jobMatch = url.pathname.match(/^\/jobs\/([^/]+)$/);
  if (jobMatch && req.method === 'GET') return getJob(res, jobMatch[1]);
  if (jobMatch || jobLogsMatch || jobCancelMatch) return methodNotAllowed(res);
  return notFound(res);
}

await mkdir(DATA_DIR, { recursive: true });

const server = http.createServer((req, res) => {
  handle(req, res).catch((error) => {
    json(res, 500, { error: 'InternalError', message: error instanceof Error ? error.message : String(error) });
  });
});

server.listen(PORT, BIND, () => {
  console.log(`OpenSphere GPU Bridge listening on ${BIND}:${PORT}`);
});
