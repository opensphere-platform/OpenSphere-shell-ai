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
  for (const rule of credentialReader.rules || []) {
    if (resources(rule).has('secrets') && !(rule.resourceNames || []).includes('oah-external-gpu-credentials')) {
      fail('ai-credential-reader secret access must be restricted to oah-external-gpu-credentials.');
    }
  }
}

if (!roleBoundToServiceAccount('ai-reader', 'ai-runtime', 'opensphere-system')) fail('ai-reader must be bound to ai-runtime.');
if (!roleBoundToServiceAccount('ai-controller', 'ai-runtime', 'opensphere-system')) fail('ai-controller must be bound to ai-runtime.');
if (!roleBoundToServiceAccount('ai-credential-reader', 'ai-runtime', 'opensphere-system')) fail('ai-credential-reader must be bound to ai-runtime.');

if (!process.exitCode) console.log('[rbac] regression checks passed');
