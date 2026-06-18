import { ApiPromise, WsProvider } from '@polkadot/api';

function toBytesArg(value) {
  if (Array.isArray(value)) return value;
  return Array.from(value);
}

function callArgNames(api, section, method) {
  const call = api.tx?.[section]?.[method];
  return call?.meta?.args?.map((arg) => arg.name.toString()) ?? [];
}

function normalizeName(name) {
  return name.replace(/_/g, '').toLowerCase();
}

export function didSupportsKeyMaterial(api) {
  return callArgNames(api, 'did', 'addKey').some((name) => normalizeName(name) === 'keymaterial');
}

export function materialForRuntime(api, keyMaterial) {
  if (didSupportsKeyMaterial(api)) return keyMaterial;
  if (keyMaterial?.Multikey) return keyMaterial.Multikey;
  throw new Error('Connected runtime does not support JWK key material');
}

export async function createApi(url) {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  const provider = new WsProvider(url);
  const api = await ApiPromise.create({ provider });
  return api;
}

export async function getFreeBalance(api, address) {
  const { data } = await api.query.system.account(address);
  return data.free.toString();
}

async function submitExtrinsic(tx, account) {
  return new Promise((resolve, reject) => {
    let unsub = null;
    tx.signAndSend(account, (result) => {
      const done = result.status?.isInBlock || result.status?.isFinalized;
      if (done || result.dispatchError) {
        if (unsub) unsub();
        resolve(result);
      }
    })
      .then((u) => {
        unsub = u;
      })
      .catch(reject);
  });
}

export async function createDid(api, account, publicKey, didSignature) {
  const tx = api.tx.did.createDid(toBytesArg(publicKey), toBytesArg(didSignature));
  return submitExtrinsic(tx, account);
}

export async function addKey(
  api,
  account,
  didId,
  keyIdSuffix,
  keyMaterial,
  roles,
  controller,
  didSignature
) {
  const material = materialForRuntime(api, keyMaterial);
  const tx = api.tx.did.addKey(
    toBytesArg(didId),
    keyIdSuffix == null ? null : toBytesArg(keyIdSuffix),
    material,
    roles,
    controller == null ? null : toBytesArg(controller),
    toBytesArg(didSignature)
  );
  return submitExtrinsic(tx, account);
}

export async function revokeKey(api, account, didId, keyId, didSignature) {
  const tx = api.tx.did.revokeKey(
    toBytesArg(didId),
    toBytesArg(keyId),
    toBytesArg(didSignature)
  );
  return submitExtrinsic(tx, account);
}

export async function deactivateDid(api, account, didId, didSignature) {
  const tx = api.tx.did.deactivateDid(toBytesArg(didId), toBytesArg(didSignature));
  return submitExtrinsic(tx, account);
}

export async function addService(
  api,
  account,
  didId,
  serviceId,
  serviceType,
  endpoint,
  didSignature
) {
  const service = {
    id: toBytesArg(serviceId),
    service_type: toBytesArg(serviceType),
    endpoint: toBytesArg(endpoint),
  };
  const tx = api.tx.did.addService(toBytesArg(didId), service, toBytesArg(didSignature));
  return submitExtrinsic(tx, account);
}

export async function removeService(api, account, didId, serviceId, didSignature) {
  const tx = api.tx.did.removeService(
    toBytesArg(didId),
    toBytesArg(serviceId),
    toBytesArg(didSignature)
  );
  return submitExtrinsic(tx, account);
}

export async function setMetadata(api, account, didId, key, value, didSignature) {
  const entry = {
    key: toBytesArg(key),
    value: toBytesArg(value),
  };
  const tx = api.tx.did.setMetadata(toBytesArg(didId), entry, toBytesArg(didSignature));
  return submitExtrinsic(tx, account);
}

export async function removeMetadata(api, account, didId, key, didSignature) {
  const tx = api.tx.did.removeMetadata(
    toBytesArg(didId),
    toBytesArg(key),
    toBytesArg(didSignature)
  );
  return submitExtrinsic(tx, account);
}

export async function rotateKey(
  api,
  account,
  didId,
  oldKeyId,
  newKeyMaterial,
  newKeyIdSuffix,
  newController,
  roles,
  didSignature
) {
  const material = materialForRuntime(api, newKeyMaterial);
  const tx = api.tx.did.rotateKey(
    toBytesArg(didId),
    toBytesArg(oldKeyId),
    material,
    newKeyIdSuffix == null ? null : toBytesArg(newKeyIdSuffix),
    newController == null ? null : toBytesArg(newController),
    roles,
    toBytesArg(didSignature)
  );
  return submitExtrinsic(tx, account);
}

export async function updateRoles(api, account, didId, keyId, roles, didSignature) {
  const tx = api.tx.did.updateRoles(
    toBytesArg(didId),
    toBytesArg(keyId),
    roles,
    toBytesArg(didSignature)
  );
  return submitExtrinsic(tx, account);
}

export async function registerSchema(
  api,
  account,
  schemaJson,
  schemaUri,
  issuerDid,
  didSignature
) {
  const tx = api.tx.schema.registerSchema(
    toBytesArg(schemaJson),
    toBytesArg(schemaUri),
    toBytesArg(issuerDid),
    toBytesArg(didSignature)
  );
  return submitExtrinsic(tx, account);
}

export async function deprecateSchema(api, account, schemaId, issuerDid, didSignature) {
  const tx = api.tx.schema.deprecateSchema(
    toBytesArg(schemaId),
    toBytesArg(issuerDid),
    toBytesArg(didSignature)
  );
  return submitExtrinsic(tx, account);
}
