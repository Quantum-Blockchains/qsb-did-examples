import bs58 from 'bs58';

function toBytes(value) {
  if (value == null) return new Uint8Array();
  if (typeof value === 'string') {
    if (value.startsWith('0x')) {
      const hex = value.slice(2);
      const out = new Uint8Array(hex.length / 2);
      for (let i = 0; i < out.length; i += 1) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      }
      return out;
    }
    return new TextEncoder().encode(value);
  }
  if (Array.isArray(value)) {
    return Uint8Array.from(value);
  }
  return new Uint8Array();
}

function toString(value) {
  return new TextDecoder().decode(toBytes(value));
}

export function didToDocument(did, details) {
  const roleMap = {
    Authentication: 'authentication',
    AssertionMethod: 'assertionMethod',
    KeyAgreement: 'keyAgreement',
    CapabilityInvocation: 'capabilityInvocation',
    CapabilityDelegation: 'capabilityDelegation',
  };

  const services = (details.services || []).map((service) => ({
    id: toString(service.id ?? service.service_id),
    service_type: toString(service.service_type ?? service.serviceType),
    endpoint: toString(service.endpoint),
  }));

  const metadata = (details.metadata || []).map((item) => ({
    key: toString(item.key),
    value: toString(item.value),
  }));

  const doc = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    version: details.version,
    deactivated: details.deactivated,
    verificationMethod: [],
    authentication: [],
    assertionMethod: [],
    keyAgreement: [],
    capabilityInvocation: [],
    capabilityDelegation: [],
    service: services,
    metadata,
  };

  (details.keys || []).forEach((key, index) => {
    const keyId = `${did}#keys-${index + 1}`;
    const publicKeyBytes = toBytes(key.public_key ?? key.publicKey);
    const publicKeyMultibase = `z${bs58.encode(publicKeyBytes)}`;
    const roles = key.roles || [];
    doc.verificationMethod.push({
      id: keyId,
      type: 'ML-DSA-44',
      controller: did,
      publicKeyMultibase,
      revoked: key.revoked ?? false,
      roles,
    });
    roles.forEach((role) => {
      const field = roleMap[role];
      if (field) doc[field].push(keyId);
    });
  });

  return doc;
}

export async function resolveDid(api, did) {
  if (api.rpc?.did?.getByString) {
    const opt = await api.rpc.did.getByString(did);
    const result = opt?.toJSON ? opt.toJSON() : null;
    if (result) return didToDocument(did, result);
  }
  const provider = getProvider(api);
  if (provider?.send) {
    const response = await provider.send('did_getByString', [did]);
    const result = response?.result ?? response;
    if (result) {
      if (typeof result === 'string' && result.startsWith('0x')) {
        const decoded = decodeDidDetails(api, result);
        if (decoded) return didToDocument(did, decoded);
      }
      if (typeof result === 'object') {
        return didToDocument(did, result);
      }
    }
  }
  return null;
}

function decodeDidDetails(api, hex) {
  const candidates = ['Option<DidDetails>', 'Option<did::DidDetails>'];
  for (const typeName of candidates) {
    try {
      const decoded = api.registry.createType(typeName, hex);
      const json = decoded.toJSON?.();
      if (json) return json;
    } catch {
      // try next candidate
    }
  }
  return null;
}

function getProvider(api) {
  return (
    api?.rpc?.provider ||
    api?.rpcCore?.provider ||
    api?._rpcCore?.provider ||
    null
  );
}
