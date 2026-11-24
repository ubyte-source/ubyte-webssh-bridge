import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verify } from 'node:crypto';
import { UAgent } from '../public/javascript/agent.js';
import * as fixtures from './fixtures.js';

const { UKey } = UAgent;
const { UWire } = UKey;
const keys = await fixtures.keys('ED25519', 'ECDSA P-256', 'ECDSA P-384', 'ECDSA P-521', 'RSA 1024', 'RSA 2048');
const curves = {
  'ECDSA P-256': ['sha256', 32],
  'ECDSA P-384': ['sha384', 48],
  'ECDSA P-521': ['sha512', 66],
};
const rsaHashes = new Map([
  [0, 'sha1'],
  [2, 'sha256'],
  [4, 'sha512'],
]);

/** Imports a generated key into a new agent. */
async function agentOf(entry) {
  const key = await UKey.inspect(new TextEncoder().encode(entry.text), entry.name);
  const loaded = await key.unlock(new TextEncoder().encode(entry.passphrase), () => {});
  const agent = new UAgent();
  agent.load(loaded.keys, loaded.blob, loaded.kind, loaded.fingerprint);
  return agent;
}

/** The generated keys that sign, the first of each kind. */
function signers(predicate) {
  const seen = new Set();
  return keys.filter((entry) => {
    if (!predicate(entry) || seen.has(entry.kind)) return false;
    seen.add(entry.kind);
    return true;
  });
}

/** Reads a userauth request and writes it again with the changes given. */
function rewrite(data, changes) {
  const reader = new UWire(data);
  const parts = { session: reader.string(), byte: reader.byte(), user: reader.text() };
  Object.assign(parts, { service: reader.text(), method: reader.text(), signed: reader.byte() });
  Object.assign(parts, { algorithm: reader.text(), blob: reader.string() }, changes);
  return UWire.concat(
    UWire.string(parts.session),
    Uint8Array.of(parts.byte),
    UWire.string(parts.user),
    UWire.string(parts.service),
    UWire.string(parts.method),
    Uint8Array.of(parts.signed),
    UWire.string(parts.algorithm),
    UWire.string(parts.blob),
  );
}

/** A generated request of a key as judge reads it, the agent waiting for its signature. */
function requestOf(entry, request) {
  return {
    data: UWire.decode64(request.data),
    flags: request.flags,
    user: request.user,
    blob: UWire.decode64(entry.blob),
    kind: entry.kind,
    state: 'authenticating',
    count: 0,
  };
}

test('agent: Ed25519 and RSA signatures verify against the generated public key, RSA with each flag', async () => {
  const flags = new Set();
  for (const entry of signers((candidate) => !candidate.kind.startsWith('ECDSA '))) {
    const agent = await agentOf(entry);
    for (const request of entry.requests) {
      agent.begin(request.user);
      const data = UWire.decode64(request.data);
      const reader = new UWire(await agent.sign(data, request.flags));
      assert.equal(reader.text(), request.algorithm);
      const signature = reader.string();
      reader.end();
      const hash = entry.kind === 'ED25519' ? null : rsaHashes.get(request.flags);
      assert.ok(verify(hash, data, entry.publicKey, signature), `${entry.name} ${request.algorithm}`);
      if (entry.kind.startsWith('RSA ')) flags.add(request.flags);
    }
  }
  assert.deepEqual([...flags].sort(), [0, 2, 4]);
});

test('agent: ECDSA signatures verify against the generated public key', async () => {
  for (const entry of signers((candidate) => candidate.kind.startsWith('ECDSA '))) {
    const agent = await agentOf(entry);
    const [hash, size] = curves[entry.kind];
    for (const request of entry.requests) {
      agent.begin(request.user);
      const data = UWire.decode64(request.data);
      const reader = new UWire(await agent.sign(data, request.flags));
      assert.equal(reader.text(), request.algorithm);
      const body = new UWire(reader.string());
      reader.end();
      const pad = (value) => Buffer.concat([Buffer.alloc(size - value.length), value]);
      const signature = Buffer.concat([pad(body.mpint()), pad(body.mpint())]);
      body.end();
      assert.ok(verify(hash, data, { key: entry.publicKey, dsaEncoding: 'ieee-p1363' }, signature), entry.name);
    }
  }
});

test('agent: judge accepts every generated request', () => {
  for (const entry of keys) {
    for (const request of entry.requests) assert.equal(UAgent.judge(requestOf(entry, request)), null, entry.name);
  }
});

test('agent: judge refuses each rule of the signing policy with its reason', () => {
  const rsa = keys.find((entry) => entry.kind.startsWith('RSA '));
  const ed25519 = keys.find((entry) => entry.kind === 'ED25519');
  const asked = (flags) => rsa.requests.find((candidate) => candidate.flags === flags);
  const sha1 = requestOf(rsa, asked(0));
  const sha512 = requestOf(rsa, asked(4));
  const edwards = requestOf(ed25519, ed25519.requests[0]);
  const cases = [
    ['state', { ...edwards, state: 'idle' }],
    ['state', { ...edwards, state: 'active' }],
    ['count', { ...edwards, count: 1 }],
    ['data', { ...edwards, data: UWire.concat(edwards.data, Uint8Array.of(0)) }],
    ['data', { ...edwards, data: rewrite(edwards.data, { session: new Uint8Array(19) }) }],
    ['data', { ...edwards, data: rewrite(edwards.data, { byte: 51 }) }],
    ['data', { ...edwards, data: rewrite(edwards.data, { service: 'ssh-userauth' }) }],
    ['data', { ...edwards, data: rewrite(edwards.data, { method: 'hostbased' }) }],
    ['data', { ...edwards, data: rewrite(edwards.data, { signed: 0 }) }],
    ['user', { ...edwards, user: 'user02' }],
    ['key', { ...edwards, blob: sha1.blob }],
    ['key', { ...edwards, blob: undefined }],
    ['flags', { ...sha1, flags: 2 }],
    ['flags', { ...sha512, flags: 0 }],
    ['flags', { ...edwards, data: rewrite(edwards.data, { algorithm: 'ssh-rsa' }) }],
  ];
  for (const [reason, request] of cases) assert.equal(UAgent.judge(request), reason, reason);
  for (const session of [20, 32, 48, 64]) {
    const data = rewrite(edwards.data, { session: new Uint8Array(session) });
    assert.equal(UAgent.judge({ ...edwards, data: data }), null, String(session));
  }
});

test('agent: refuses a second signature on one WebSocket and signs again on the next', async () => {
  const entry = signers((candidate) => candidate.kind === 'ED25519')[0];
  const request = entry.requests[0];
  const data = UWire.decode64(request.data);
  const agent = await agentOf(entry);
  agent.begin(request.user);
  assert.notEqual(await agent.sign(data, request.flags), null);
  assert.equal(await agent.sign(data, request.flags), null);
  agent.begin(request.user);
  const [first, second] = await Promise.all([agent.sign(data, request.flags), agent.sign(data, request.flags)]);
  assert.notEqual(first, null);
  assert.equal(second, null);
});

test('agent: refuses before a WebSocket begins, once the shell is ready, and without a key', async () => {
  const entry = signers((candidate) => candidate.kind === 'ED25519')[0];
  const request = entry.requests[0];
  const data = UWire.decode64(request.data);
  const agent = await agentOf(entry);
  assert.equal(await agent.sign(data, request.flags), null);
  agent.begin(request.user);
  agent.ready();
  assert.equal(await agent.sign(data, request.flags), null);
  agent.forget();
  agent.begin(request.user);
  assert.equal(await agent.sign(data, request.flags), null);
});

test('agent: the identity is the blob in base64 until the key is forgotten', async () => {
  const entry = keys[0];
  const agent = await agentOf(entry);
  assert.equal(agent.identity(), entry.blob);
  assert.equal(agent.kind(), entry.kind);
  assert.equal(agent.fingerprint(), entry.fingerprint);
  agent.forget();
  assert.equal(agent.identity(), undefined);
  assert.equal(agent.kind(), undefined);
  assert.equal(agent.fingerprint(), undefined);
});

test('agent: judge refuses a request whose key is only the start of the loaded one, or longer than it', () => {
  const ed25519 = keys.find((entry) => entry.kind === 'ED25519');
  const request = requestOf(ed25519, ed25519.requests[0]);
  assert.equal(UAgent.judge({ ...request, blob: UWire.concat(request.blob, Uint8Array.of(0)) }), 'key');
  assert.equal(UAgent.judge({ ...request, blob: request.blob.subarray(0, request.blob.length - 1) }), 'key');
});

test('agent: judge refuses a request for another key of the same length', () => {
  const ed25519 = keys.find((entry) => entry.kind === 'ED25519');
  const request = requestOf(ed25519, ed25519.requests[0]);
  const other = request.blob.slice();
  other[other.length - 1] ^= 1;
  assert.equal(UAgent.judge({ ...request, blob: other }), 'key');
});
