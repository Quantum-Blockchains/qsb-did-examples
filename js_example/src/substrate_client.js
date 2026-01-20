import { ApiPromise, WsProvider } from '@polkadot/api';

function toBytesArg(value) {
  if (Array.isArray(value)) return value;
  return Array.from(value);
}

export async function createApi(url) {
  if (process.env.SSL_INSECURE === '1') {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  }
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

export async function addService(api, account, didId, serviceId, serviceType, endpoint) {
  const service = {
    id: toBytesArg(serviceId),
    service_type: toBytesArg(serviceType),
    endpoint: toBytesArg(endpoint),
  };
  const tx = api.tx.did.addService(toBytesArg(didId), service);
  return submitExtrinsic(tx, account);
}

export async function removeService(api, account, didId, serviceId) {
  const tx = api.tx.did.removeService(toBytesArg(didId), toBytesArg(serviceId));
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
