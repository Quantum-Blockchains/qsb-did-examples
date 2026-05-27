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

function encodeUvarint(value) {
  const out = [];
  let v = Number(value) >>> 0;
  while (true) {
    let b = v & 0x7f;
    v >>>= 7;
    if (v !== 0) b |= 0x80;
    out.push(b);
    if (v === 0) break;
  }
  return Uint8Array.from(out);
}

function toMultikey(publicKey, codec) {
  if (codec == null) return null;
  const raw = toBytes(publicKey);
  const prefix = encodeUvarint(codec);
  const out = new Uint8Array(prefix.length + raw.length);
  out.set(prefix, 0);
  out.set(raw, prefix.length);
  return `u${Buffer.from(out).toString('base64url')}`;
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
    type: toString(service.service_type ?? service.serviceType ?? service.type),
    serviceEndpoint: toString(service.endpoint ?? service.serviceEndpoint),
  }));

  const metadata = (details.metadata || []).map((item) => ({
    key: toString(item.key),
    value: toString(item.value),
  }));

  const doc = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: did,
    verificationMethod: [],
    authentication: [],
    assertionMethod: [],
    keyAgreement: [],
    capabilityInvocation: [],
    capabilityDelegation: [],
    service: services,
    metadata,
  };

  (details.keys || [])
    .filter((key) => !(key.revoked ?? false))
    .forEach((key) => {
    const keyId = toString(key.key_id ?? key.keyId);
    const controller = toString(key.controller ?? did);
    const publicKeyBytes = toBytes(key.public_key ?? key.publicKey);
    const codec = key.multicodec ?? null;
    const publicKeyMultibase = toMultikey(publicKeyBytes, codec) ?? `z${bs58.encode(publicKeyBytes)}`;
    const roles = key.roles || [];
    doc.verificationMethod.push({
      id: keyId,
      type: 'Multikey',
      controller,
      publicKeyMultibase,
    });
    roles.forEach((role) => {
      const field = roleMap[role];
      if (field) doc[field].push(keyId);
    });
  });

  return doc;
}

export async function resolveDid(api, did) {
  const success = (details) => ({
    didDocument: didToDocument(did, details),
    didDocumentMetadata: {
      deactivated: details?.deactivated ?? false,
      versionId: details?.version ?? 0,
    },
    didResolutionMetadata: {
      contentType: 'application/did+ld+json',
      error: null,
    },
  });
  const notFound = () => ({
    didDocument: null,
    didDocumentMetadata: {
      deactivated: false,
      versionId: 0,
    },
    didResolutionMetadata: {
      contentType: null,
      error: 'notFound',
    },
  });

  if (api.rpc?.did?.getByString) {
    const opt = await api.rpc.did.getByString(did);
    const result = opt?.toJSON ? opt.toJSON() : null;
    if (result) return success(result);
  }
  const provider = getProvider(api);
  if (provider?.send) {
    const response = await provider.send('did_getByString', [did]);
    const result = response?.result ?? response;
    if (result) {
      if (typeof result === 'string' && result.startsWith('0x')) {
        const decoded = decodeDidDetails(api, result);
        if (decoded) return success(decoded);
      }
      if (typeof result === 'object') {
        return success(result);
      }
    }
  }
  return notFound();
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
