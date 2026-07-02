const fs = require('node:fs');
const path = require('node:path');
const yaml = require('js-yaml');

const file = path.resolve(__dirname, '..', 'rbac.yaml');
const docs = yaml.loadAll(fs.readFileSync(file, 'utf8')).filter(Boolean);

function fail(message) {
  console.error(`[rbac] ${message}`);
  process.exitCode = 1;
}

function role(name, kind = 'ClusterRole') {
  return docs.find((doc) => doc.kind === kind && doc.metadata?.name === name);
}

function bindingsTo(roleName) {
  return docs.filter((doc) => {
    if (!['RoleBinding', 'ClusterRoleBinding'].includes(doc.kind)) return false;
    return doc.roleRef?.name === roleName;
  });
}

function serviceAccount(name, namespace) {
  return docs.find((doc) => doc.kind === 'ServiceAccount' && doc.metadata?.name === name && doc.metadata?.namespace === namespace);
}

function bindingHasSubject(binding, kind, name, namespace) {
  return (binding.subjects || []).some((subject) =>
    subject.kind === kind && subject.name === name && (!namespace || subject.namespace === namespace));
}

function roleBoundToServiceAccount(roleName, serviceAccountName, namespace) {
  return bindingsTo(roleName).some((binding) => bindingHasSubject(binding, 'ServiceAccount', serviceAccountName, namespace));
}

function verbs(rule) {
  return new Set(rule.verbs || []);
}

function resources(rule) {
  return new Set(rule.resources || []);
}

function hasRule(target, apiGroup, resource, requiredVerbs) {
  return (target?.rules || []).some((rule) => {
    const groups = rule.apiGroups || [];
    if (!groups.includes(apiGroup)) return false;
    if (!resources(rule).has(resource)) return false;
    const ruleVerbs = verbs(rule);
    return requiredVerbs.every((verb) => ruleVerbs.has(verb));
  });
}

const reader = role('ai-reader');
if (!reader) fail('ai-reader ClusterRole is missing.');
if (reader) {
  for (const rule of reader.rules || []) {
    const ruleVerbs = verbs(rule);
    const ruleResources = resources(rule);
    for (const forbidden of ['create', 'update', 'patch', 'delete', 'impersonate']) {
      if (forbidden === 'create' && rule.apiGroups?.includes('authorization.k8s.io') && ruleResources.has('selfsubjectaccessreviews')) continue;
      if (ruleVerbs.has(forbidden)) fail(`ai-reader must not grant ${forbidden}.`);
    }
    if (ruleResources.has('secrets')) fail('ai-reader must not grant secrets access.');
  }
}

const controller = role('ai-controller');
if (!controller) fail('ai-controller ClusterRole is missing.');
if (controller && !hasRule(controller, 'backbone.opensphere.io', 'backboneclaims', ['create', 'update', 'patch'])) {
  fail('ai-controller must be able to create/update/patch BackboneClaim resources.');
}
if (controller && !hasRule(controller, 'datasciencepipelinesapplications.opendatahub.io', 'datasciencepipelinesapplications', ['create', 'update', 'patch'])) {
  fail('ai-controller must be able to create/update/patch DataSciencePipelinesApplication resources.');
}
if (reader && !hasRule(reader, 'datasciencepipelinesapplications.opendatahub.io', 'datasciencepipelinesapplications/api', ['get'])) {
  fail('ai-reader must be able to read the DataSciencePipelinesApplication API subresource for KFP proxy access.');
}
if (controller && !hasRule(controller, 'networking.k8s.io', 'networkpolicies', ['create', 'update', 'patch'])) {
  fail('ai-controller must be able to create/update/patch NetworkPolicy resources for support-service compatibility.');
}

if (!serviceAccount('ai-runtime', 'opensphere-system')) fail('ai-runtime ServiceAccount is missing.');

const installer = role('ai-installer');
if (!installer) fail('ai-installer ClusterRole is missing.');
if (bindingsTo('ai-installer').length) fail('ai-installer must not be bound by default.');

const admin = role('ai-admin');
if (!admin) fail('ai-admin ClusterRole is missing.');
if (bindingsTo('ai-admin').length) fail('ai-admin must not be bound by default.');

const credentialReader = role('ai-credential-reader', 'Role');
if (!credentialReader) fail('ai-credential-reader Role is missing.');
if (credentialReader) {
  const allowedSecrets = new Set([
    'oah-external-gpu-credentials',
    'ai-hub-backbone-postgres',
    'ai-hub-backbone-postgres-app',
    'oah-dspa-postgres',
    'ai-hub-backbone-rustfs',
    'ai-hub-kserve-s3',
    'ds-pipelines-proxy-tls-oah-dspa',
    'ds-pipelines-envoy-proxy-tls-oah-dspa',
    'opensphere-wildcard-tls',
    'shell-service-token',
  ]);
  for (const rule of credentialReader.rules || []) {
    if (resources(rule).has('secrets')) {
      const names = rule.resourceNames || [];
      if (!names.length) fail('ai-credential-reader secret access must use resourceNames.');
      for (const name of names) {
        if (!allowedSecrets.has(name)) fail(`ai-credential-reader contains unexpected secret resourceName ${name}.`);
      }
      for (const name of allowedSecrets) {
        if (!names.includes(name)) fail(`ai-credential-reader is missing secret resourceName ${name}.`);
      }
    }
  }
}

if (!roleBoundToServiceAccount('ai-reader', 'ai-runtime', 'opensphere-system')) fail('ai-reader must be bound to ai-runtime.');
if (!roleBoundToServiceAccount('ai-controller', 'ai-runtime', 'opensphere-system')) fail('ai-controller must be bound to ai-runtime.');
if (!roleBoundToServiceAccount('ai-credential-reader', 'ai-runtime', 'opensphere-system')) fail('ai-credential-reader must be bound to ai-runtime.');
if (!roleBoundToServiceAccount('ai-support-service-writer', 'ai-runtime', 'opensphere-system')) fail('ai-support-service-writer must be bound to ai-runtime.');

const supportWriter = role('ai-support-service-writer', 'Role');
if (!supportWriter) fail('ai-support-service-writer Role is missing.');
if (supportWriter) {
  if (!hasRule(supportWriter, '', 'secrets', ['create'])) fail('ai-support-service-writer must be able to create support Secrets.');
  for (const secretName of ['ai-hub-kserve-s3', 'ds-pipelines-proxy-tls-oah-dspa', 'ds-pipelines-envoy-proxy-tls-oah-dspa']) {
    const canPatchSecret = (supportWriter.rules || []).some((rule) => (
      (rule.apiGroups || []).includes('')
      && resources(rule).has('secrets')
      && (rule.resourceNames || []).includes(secretName)
      && ['get', 'update', 'patch'].every((verb) => verbs(rule).has(verb))
    ));
    if (!canPatchSecret) fail(`ai-support-service-writer must be able to get/update/patch ${secretName}.`);
  }
  if (!hasRule(supportWriter, '', 'serviceaccounts', ['get', 'update', 'patch'])) fail('ai-support-service-writer must be able to patch ai-runtime ServiceAccount.');
}

if (!process.exitCode) console.log('[rbac] regression checks passed');
