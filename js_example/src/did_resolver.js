import bs58 from 'bs58';

function toBytes(value) {
  if (value == null) return new Uint8Array();
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
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

function decodeStoredBytes(value) {
  if (typeof value !== 'string' || !value.startsWith('0x')) {
    return value;
  }
  const bytes = toBytes(value);
  const text = toString(bytes);
  const printableAscii = /^[\x20-\x7e]*$/.test(text);
  return printableAscii && (text.startsWith('u') || text.startsWith('{')) ? text : bytes;
}

function parseJsonBytes(value) {
  try {
    return JSON.parse(toString(value));
  } catch {
    return toString(value);
  }
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

function decodeUvarint(bytes) {
  let value = 0;
  let shift = 0;
  for (let i = 0; i < bytes.length; i += 1) {
    const byte = bytes[i];
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      return { value, offset: i + 1 };
    }
    shift += 7;
  }
  throw new Error('Invalid uvarint');
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

export function decodeMultikey(value) {
  const decodedValue = decodeStoredBytes(value);
  const text = typeof decodedValue === 'string' ? decodedValue : toString(decodedValue);
  if (!text.startsWith('u')) {
    return { multicodec: null, publicKey: toBytes(decodedValue) };
  }
  const bytes = Uint8Array.from(Buffer.from(text.slice(1), 'base64url'));
  const { value: multicodec, offset } = decodeUvarint(bytes);
  return { multicodec, publicKey: bytes.slice(offset) };
}

function didIdBytes(did) {
  const prefix = 'did:qsb:';
  if (!did.startsWith(prefix)) {
    throw new Error('DID must start with did:qsb:');
  }
  const didId = bs58.decode(did.slice(prefix.length));
  if (didId.length !== 32) {
    throw new Error('DID id must decode to 32 bytes');
  }
  return didId;
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
      const material = normalizeKeyMaterial(key);
      const roles = key.roles || [];
      const vm = {
        id: keyId,
        controller,
      };
      if (material.type === 'Jwk') {
        vm.type = 'JsonWebKey2020';
        vm.publicKeyJwk = parseJsonBytes(material.publicKeyJwk);
      } else {
        const publicKeyMultibase =
          toMultikey(material.publicKey, material.multicodec) ??
          `z${bs58.encode(material.publicKey)}`;
        vm.type = 'Multikey';
        vm.publicKeyMultibase = publicKeyMultibase;
      }
      doc.verificationMethod.push(vm);
      roles.forEach((role) => {
        const field = roleMap[role];
        if (field) doc[field].push(keyId);
      });
    });

  return doc;
}

function normalizeKeyMaterial(key) {
  const material = key.key_material ?? key.keyMaterial;
  const multikey =
    material?.Multikey ??
    material?.multikey ??
    material?.multikeyValue ??
    material?.multikey_value ??
    null;
  if (multikey) {
    const raw = Array.isArray(multikey)
      ? multikey[1]
      : typeof multikey === 'string'
        ? multikey
        : multikey.public_key ?? multikey.publicKey ?? multikey;
    const decoded = decodeMultikey(raw);
    const multicodec = Array.isArray(multikey)
      ? Number(multikey[0])
      : multikey.multicodec ?? multikey.multicodecValue ?? decoded.multicodec ?? null;
    return {
      type: 'Multikey',
      multicodec,
      publicKey: decoded.publicKey,
    };
  }

  const jwk =
    material?.Jwk ??
    material?.jwk ??
    material?.jwkValue ??
    material?.jwk_value ??
    null;
  if (jwk) {
    const raw =
      typeof jwk === 'string'
        ? jwk
        : jwk.public_key_jwk ?? jwk.publicKeyJwk ?? jwk;
    return {
      type: 'Jwk',
      publicKeyJwk: toBytes(decodeStoredBytes(raw)),
    };
  }

  return {
    type: 'Multikey',
    multicodec: key.multicodec ?? null,
    publicKey: toBytes(key.public_key ?? key.publicKey),
  };
}

export async function resolveDid(api, did) {
  const success = (details, warning = null) => ({
    didDocument: didToDocument(did, details),
    didDocumentMetadata: {
      deactivated: details?.deactivated ?? false,
      versionId: details?.version ?? 0,
    },
    didResolutionMetadata: {
      contentType: 'application/did+ld+json',
      error: null,
      ...(warning ? { warning } : {}),
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

  try {
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
          if (result.error) {
            const fallback = await queryDidRecords(api, did);
            if (fallback) {
              return success(
                fallback,
                'did_getByString returned an error; resolved through Did.DidRecords storage query'
              );
            }
          }
          return success(result);
        }
      }
    }
  } catch (error) {
    const result = await queryDidRecords(api, did);
    if (result) {
      return success(
        result,
        'did_getByString failed; resolved through Did.DidRecords storage query'
      );
    }
    return {
      didDocument: null,
      didDocumentMetadata: {
        deactivated: false,
        versionId: 0,
      },
      didResolutionMetadata: {
        contentType: null,
        error: 'runtimeApiDecodeError',
        message: error.message,
      },
    };
  }
  return notFound();
}

async function queryDidRecords(api, did) {
  const query = api.query?.did?.didRecords;
  if (!query) return null;
  const record = await query(didIdBytes(did));
  if (record?.isNone) return null;
  const value = record?.unwrap ? record.unwrap() : record;
  return value?.toJSON ? value.toJSON() : null;
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
