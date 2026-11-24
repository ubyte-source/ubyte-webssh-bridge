import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createPrivateKey } from 'node:crypto';
import { UKey } from '../public/javascript/key.js';
import * as fixtures from './fixtures.js';

const { UWire, UDer, UBcrypt, Refusal } = UKey;
const keys = await fixtures.keys();
const refusals = await fixtures.refusals();
const encode = (text) => new TextEncoder().encode(text);
const nothing = () => {};
const kinds = ['ED25519', 'ECDSA P-256', 'ECDSA P-384', 'ECDSA P-521', 'RSA 2048'];

/** Reads a text to its refusal code, or `loaded` when the page imports it. */
async function judge(text, passphrase) {
  try {
    const key = await UKey.inspect(encode(text), 'id_test');
    await key.unlock(encode(passphrase), nothing);
    return 'loaded';
  } catch (error) {
    assert.ok(error instanceof Refusal, String(error));
    return error.code;
  }
}

/** Writes an armour around a body. */
function armour(label, body) {
  return `-----BEGIN ${label}-----\n${UWire.encode64(body).replace(/.{1,70}/g, '$&\n')}-----END ${label}-----\n`;
}

/** Reads the body of an armoured text. */
function bodyOf(text) {
  return UWire.decode64(text.split('\n').filter((line) => !line.startsWith('-----')).join(''));
}

/** Reads the parts of an OpenSSH key file in their order. */
function opensshOf(text) {
  const reader = new UWire(bodyOf(text));
  const parts = {
    magic: reader.bytes(15),
    cipher: reader.text(),
    kdf: reader.text(),
    options: reader.string(),
    count: reader.uint32(),
    header: reader.string(),
    section: reader.string(),
  };
  reader.end();
  return parts;
}

/** Writes an OpenSSH key file from its parts, with the bytes of `trailer` after the section. */
function openssh({ magic, cipher, kdf, options, count, header, section, trailer = new Uint8Array(0) }) {
  const strings = [cipher, kdf, options].map((part) => UWire.string(part));
  const tail = [UWire.uint32(count), UWire.string(header), UWire.string(section), trailer];
  return armour('OPENSSH PRIVATE KEY', UWire.concat(magic, ...strings, ...tail));
}

/** Rewrites the kdf options of an encrypted OpenSSH key with other rounds. */
function withRounds(text, rounds) {
  const parts = opensshOf(text);
  const salt = new UWire(parts.options).string();
  return openssh({ ...parts, options: UWire.concat(UWire.string(salt), UWire.uint32(rounds)) });
}

/** Writes a PKCS #1 key whose modulus has the given bits; the other numbers are not a key. */
function rsaOfBits(bits) {
  const n = new Uint8Array(Math.ceil(bits / 8)).fill(0xff);
  n[0] = 0xff >> (8 * n.length - bits);
  const integer = (bytes) => UDer.write(UDer.INTEGER, bytes[0] >= 0x80 ? UWire.concat(Uint8Array.of(0), bytes) : bytes);
  const small = integer(Uint8Array.of(3));
  const body = UDer.write(UDer.SEQUENCE, integer(Uint8Array.of(0)), integer(n), ...Array(7).fill(small));
  return armour('RSA PRIVATE KEY', body);
}

test('key: every fixture key is inspected with its format, kind, comment and encryption', async () => {
  for (const entry of keys) {
    const key = await UKey.inspect(encode(entry.text), entry.name);
    assert.equal(key.name, entry.name);
    assert.equal(key.format, entry.format, entry.name);
    assert.equal(key.kind, entry.kind, entry.name);
    assert.equal(key.encrypted, entry.cipher !== 'none', entry.name);
    assert.equal(key.comment, key.encrypted ? '' : entry.comment, entry.name);
    key.discard();
  }
});

test('key: the blob and fingerprint are known before the passphrase where the file holds the public key', async () => {
  for (const entry of keys) {
    const key = await UKey.inspect(encode(entry.text), entry.name);
    if (entry.format === 'openssh' || entry.kind.startsWith('RSA ')) assert.notEqual(key.blob, undefined, entry.name);
    if (key.blob !== undefined) {
      assert.equal(UWire.encode64(key.blob), entry.blob, entry.name);
      assert.equal(key.fingerprint, entry.fingerprint, entry.name);
    }
    key.discard();
  }
});

test('key: every fixture key is imported with its passphrase, giving its blob, kind and fingerprint', async () => {
  for (const entry of keys) {
    const key = await UKey.inspect(encode(entry.text), entry.name);
    const loaded = await key.unlock(encode(entry.passphrase), nothing);
    assert.equal(UWire.encode64(loaded.blob), entry.blob, entry.name);
    assert.equal(loaded.fingerprint, entry.fingerprint, entry.name);
    assert.equal(loaded.kind, entry.kind, entry.name);
    for (const cryptoKey of loaded.keys.values()) {
      assert.equal(cryptoKey.extractable, false, entry.name);
      assert.deepEqual(cryptoKey.usages, ['sign'], entry.name);
    }
  }
});

test('key: an RSA key is imported once per signature algorithm with its hash', async () => {
  const entry = keys.find((candidate) => candidate.kind.startsWith('RSA ') && candidate.format === 'openssh');
  const key = await UKey.inspect(encode(entry.text), entry.name);
  const loaded = await key.unlock(encode(entry.passphrase), nothing);
  const hashes = [...loaded.keys].map(([algorithm, cryptoKey]) => [algorithm, cryptoKey.algorithm.hash.name]);
  assert.deepEqual(hashes, [
    ['ssh-rsa', 'SHA-1'],
    ['rsa-sha2-256', 'SHA-256'],
    ['rsa-sha2-512', 'SHA-512'],
  ]);
});

test('key: a wrong passphrase is refused passphrase for each cipher and the right one then unlocks', async () => {
  const ciphers = new Set();
  for (const entry of keys.filter((candidate) => candidate.cipher !== 'none')) {
    const key = await UKey.inspect(encode(entry.text), entry.name);
    await assert.rejects(key.unlock(encode(`${entry.passphrase}x`), nothing), { code: 'passphrase' });
    await assert.rejects(key.unlock(new Uint8Array(0), nothing), { code: 'passphrase' });
    const loaded = await key.unlock(encode(entry.passphrase), nothing);
    assert.equal(loaded.fingerprint, entry.fingerprint, entry.name);
    ciphers.add(entry.cipher);
  }
  assert.deepEqual([...ciphers].sort(), ['aes128-ctr', 'aes192-ctr', 'aes256-ctr']);
});

test('key: the bcrypt rounds are reported to the progress callback one by one', async () => {
  const entry = keys.find((candidate) => candidate.cipher !== 'none');
  const key = await UKey.inspect(encode(entry.text), entry.name);
  const reports = [];
  await key.unlock(encode(entry.passphrase), (round, rounds) => reports.push([round, rounds]));
  assert.ok(reports.length > 0);
  reports.forEach(([round, rounds], index) => {
    assert.equal(round, index + 1);
    assert.equal(rounds, reports.length);
  });
});

test('key: every fixture refusal is refused with its code', async () => {
  for (const entry of refusals) {
    assert.equal(await judge(entry.text, entry.passphrase), entry.refusal, entry.name);
  }
});

test('key: refuses a file over 16384 bytes before reading it', async () => {
  const entry = keys.find((candidate) => candidate.format === 'openssh' && candidate.cipher === 'none');
  const bytes = encode(entry.text.padEnd(16385, '\n'));
  await assert.rejects(UKey.inspect(bytes, entry.name), { code: 'too-large' });
  assert.ok(bytes.every((byte) => byte === 0));
  const exact = await UKey.inspect(encode(entry.text.padEnd(16384, '\n')), entry.name);
  assert.equal(exact.fingerprint, entry.fingerprint);
});

test('key: refuses bcrypt rounds over 2048 and reads 2048', async () => {
  const entry = keys.find((candidate) => candidate.cipher !== 'none' && candidate.format === 'openssh');
  const key = await UKey.inspect(encode(withRounds(entry.text, 2048)), entry.name);
  assert.equal(key.fingerprint, entry.fingerprint);
  key.discard();
  await assert.rejects(UKey.inspect(encode(withRounds(entry.text, 2049)), entry.name), { code: 'rounds' });
});

test('key: refuses an RSA modulus outside 1024-16384 bits', async () => {
  for (const [bits, kind] of [
    [1024, 'RSA 1024'],
    [16384, 'RSA 16384'],
  ]) {
    const key = await UKey.inspect(encode(rsaOfBits(bits)), 'id_rsa');
    assert.equal(key.kind, kind);
    key.discard();
  }
  for (const bits of [1023, 16385]) {
    await assert.rejects(UKey.inspect(encode(rsaOfBits(bits)), 'id_rsa'), { code: 'rsa-size' }, String(bits));
  }
});

test('key: a text without a private key armour is refused with what it is', async () => {
  const blob = keys[0].blob;
  const cases = [
    ['plain text', 'not-a-key'],
    [`ssh-ed25519 ${blob} user01@example.test\n`, 'public-key'],
    [armour('PUBLIC KEY', Uint8Array.of(1)), 'public-key'],
    [armour('CERTIFICATE', Uint8Array.of(1)), 'not-a-key'],
    [armour('DSA PRIVATE KEY', Uint8Array.of(1)), 'dsa'],
    [armour('ENCRYPTED PRIVATE KEY', Uint8Array.of(1)), 'cipher'],
    [armour('OPENSSH PRIVATE KEY', new Uint8Array(3)).split('-----END')[0], 'malformed'],
    [armour('OPENSSH PRIVATE KEY', new Uint8Array(3)).replace('AAAA', 'AA*A'), 'malformed'],
    [armour('OPENSSH PRIVATE KEY', encode('openssh-key-v1')), 'malformed'],
    [armour('PRIVATE KEY', Uint8Array.of(0x30, 0x00)), 'malformed'],
  ];
  for (const [text, code] of cases) assert.equal(await judge(text, ''), code, text);
});

test('key: a PKCS #8 DSA key is refused dsa, another algorithm or a part of the wrong size malformed', async () => {
  const octets = (length) => UDer.write(UDer.OCTET_STRING, new Uint8Array(length).fill(7));
  const ec = (...parts) => UDer.write(UDer.SEQUENCE, UDer.write(UDer.INTEGER, Uint8Array.of(1)), ...parts);
  const bits = (length) => UDer.write(UDer.BIT_STRING, Uint8Array.of(0, 4), new Uint8Array(length));
  const point = (length) => UDer.write(UDer.EXPLICIT_1, bits(length));
  const p256 = ['1.2.840.10045.2.1', '1.2.840.10045.3.1.7'];
  const cases = [
    ['dsa', ['1.2.840.10040.4.1'], UDer.write(UDer.INTEGER, Uint8Array.of(1))],
    ['malformed', ['1.3.101.113'], octets(57)],
    ['malformed', ['1.3.101.112'], octets(31)],
    ['malformed', p256, ec(octets(33))],
    ['malformed', p256, ec(octets(32), point(63))],
    ['curve', ['1.2.840.10045.2.1', '1.3.132.0.33'], ec(octets(28))],
  ];
  for (const [code, identifiers, key] of cases) {
    assert.equal(await judge(armour('PRIVATE KEY', UDer.pkcs8(identifiers, key)), ''), code, identifiers.join());
  }
});

test('key: the arrays UKey received are all zero afterwards', async () => {
  for (const entry of [...keys, ...refusals]) {
    const received = [encode(entry.text)];
    try {
      const key = await UKey.inspect(received[0], entry.name);
      received.push(encode(entry.passphrase));
      await key.unlock(received[1], nothing);
    } catch (error) {
      assert.ok(error instanceof Refusal, String(error));
    }
    for (const bytes of received) assert.ok(bytes.every((byte) => byte === 0), entry.name);
  }
});

test('key: a key refused after inspection is discarded and refuses to unlock again', async () => {
  const entry = keys.find((candidate) => candidate.format === 'openssh' && candidate.cipher === 'none');
  const key = await UKey.inspect(encode(entry.text), entry.name);
  key.discard();
  await assert.rejects(key.unlock(new Uint8Array(0), nothing), { code: 'malformed' });
});

test('key: armoured accepts every fixture key and a PuTTY key, and refuses a public key line and plain text', () => {
  for (const entry of keys) assert.ok(UKey.armoured(entry.text), entry.name);
  const putty = refusals.find((entry) => entry.refusal === 'putty');
  assert.ok(UKey.armoured(putty.text));
  assert.ok(!UKey.armoured(`ssh-ed25519 ${keys[0].blob} user01@example.test`));
  assert.ok(!UKey.armoured('user01 types a command'));
});

test('key: signable is true for every kind under the crypto.subtle of Node', async () => {
  for (const kind of kinds) assert.equal(await UKey.signable(kind), true, kind);
});

test('key: signable is false for Ed25519 and one ECDSA curve under a subtle that rejects them', async () => {
  const subtle = {
    generateKey: async (algorithm) => {
      if (algorithm.name === 'Ed25519' || algorithm.namedCurve === 'P-384') throw new Error('NotSupportedError');
      return {};
    },
  };
  assert.equal(await UKey.signable('ED25519', subtle), false);
  assert.equal(await UKey.signable('ECDSA P-384', subtle), false);
  assert.equal(await UKey.signable('ECDSA P-256', subtle), true);
  assert.equal(await UKey.signable('RSA 2048', subtle), true);
});

test('key: signable is false without subtle, and the unsupported refusal names each kind', async () => {
  const texts = [
    'This browser cannot sign with Ed25519 keys.',
    'This browser cannot sign with ECDSA P-256 keys.',
    'This browser cannot sign with ECDSA P-384 keys.',
    'This browser cannot sign with ECDSA P-521 keys.',
    'This browser cannot sign with RSA keys.',
  ];
  for (const [index, kind] of kinds.entries()) {
    assert.equal(await UKey.signable(kind, null), false, kind);
    const refusal = new Refusal('unsupported', kind);
    assert.equal(refusal.text, texts[index]);
    assert.equal(refusal.command, null);
  }
});

test('key: the refusals that a command fixes carry it', () => {
  assert.equal(new Refusal('dsa').command, 'ssh-keygen -t ed25519');
  assert.equal(new Refusal('putty').command, 'puttygen <file> -O private-openssh-new -o <file>.openssh');
  for (const code of ['pem-encrypted', 'cipher', 'kdf', 'rounds']) {
    assert.equal(new Refusal(code).command, 'ssh-keygen -p -f <file>', code);
  }
  assert.equal(new Refusal('public-key').text, 'This is a public key; drop the private one.');
  assert.equal(new Refusal('passphrase').text, 'Wrong passphrase.');
});

/** Inspects the fixture refused with a code under a name and returns the refusal. */
async function refusal(code, name) {
  const entry = refusals.find((candidate) => candidate.refusal === code);
  try {
    await UKey.inspect(encode(entry.text), name);
  } catch (error) {
    return error;
  }
  assert.fail(`${entry.name} was not refused`);
}

/** Returns the words a POSIX shell reads after the program of a command. */
function words(command) {
  const output = execFileSync('sh', ['-c', command.replace(/^\S+/, "printf '%s\\0'")], { encoding: 'utf8' });
  return output.split('\0').slice(0, -1);
}

test('key: the command of a refused file names it, a pasted key keeps <file>', async () => {
  assert.equal((await refusal('cipher', 'id_rsa')).command, 'ssh-keygen -p -f id_rsa');
  const putty = 'puttygen key.ppk -O private-openssh-new -o key.ppk.openssh';
  assert.equal((await refusal('putty', 'key.ppk')).command, putty);
  assert.equal((await refusal('kdf', 'pasted key')).command, 'ssh-keygen -p -f <file>');
  assert.equal(
    (await refusal('putty', 'pasted key')).command,
    'puttygen <file> -O private-openssh-new -o <file>.openssh',
  );
  assert.equal((await refusal('dsa', 'id_dsa')).command, 'ssh-keygen -t ed25519');
  assert.equal((await refusal('malformed', 'id_test')).command, null);
  const refused = new Refusal('rounds');
  assert.equal(refused.name('id_ed25519'), refused);
});

test('key: a file name with spaces, quotes or shell characters is quoted so a shell reads it as one word', async () => {
  const names = [
    ["user01 key's.pem", `'user01 key'\\''s.pem'`],
    ['a$&b;$(id)`id`|<>*?~"c".ppk', `'a$&b;$(id)\`id\`|<>*?~"c".ppk'`],
    ['-o.ppk', './-o.ppk'],
    ["-x 'y'.ppk", `'./-x '\\''y'\\''.ppk'`],
    ['two\nlines.ppk', `'two\nlines.ppk'`],
    ['clé.ppk', `'clé.ppk'`],
    ['', `''`],
  ];
  for (const [name, quoted] of names) {
    const keygen = await refusal('pem-encrypted', name);
    assert.equal(keygen.command, `ssh-keygen -p -f ${quoted}`, name);
    const file = name.startsWith('-') ? `./${name}` : name;
    assert.deepEqual(words(keygen.command), ['-p', '-f', file], name);
    const putty = await refusal('putty', name);
    assert.deepEqual(words(putty.command), [file, '-O', 'private-openssh-new', '-o', `${file}.openssh`], name);
  }
});

test('key: bcrypt pbkdf equals the vectors of the OpenBSD reference', async () => {
  const vectors = [
    [12, 'password', 'salt', '1ae42c05d487bc02f64921a4ebe4ea93bcacfe135fda99974c06b7b01fae149a'],
    [3, 'passwordy\0PASSWORD\0', 'salty\0SALT\0', '7f310bd3e78c3280c59ce4595211a2928e8d4ec744c1ed2efc9f764e3388e0ad'],
    [
      8,
      'секретное слово',
      'посолить немножко',
      '8df43fc6fe131fc47f0c9e39224bd94c70b6fcc8ee8135faddf61156e6cb2733ea765f315a3e1e4afc35bf8687d189' +
        '254c1e05a6fe80c0617f9183d67260d6a115c6c94e3603e2303fbb43a76a64523ffda686b1d4518543',
    ],
  ];
  for (const [rounds, passphrase, salt, want] of vectors) {
    const key = await UBcrypt.pbkdf(encode(passphrase), encode(salt), rounds, want.length / 2, nothing);
    assert.equal(Buffer.from(key).toString('hex'), want);
  }
});

test('key: the PKCS #8 writer gives DER the reader reads back', () => {
  const der = UDer.pkcs8(['1.2.840.10045.2.1', '1.3.132.0.35'], Uint8Array.of(1, 2, 3));
  const outer = new UDer(der);
  const info = outer.sequence();
  outer.end();
  assert.equal(info.integer().length, 0);
  const algorithm = info.sequence();
  assert.equal(algorithm.oid(), '1.2.840.10045.2.1');
  assert.equal(algorithm.oid(), '1.3.132.0.35');
  algorithm.end();
  assert.deepEqual([...info.octets()], [1, 2, 3]);
  info.end();
});

test('key: the DER reader refuses a wrong tag, a short element and a long length form past three bytes', () => {
  assert.throws(() => new UDer(Uint8Array.of(0x04, 0x00)).sequence(), RangeError);
  assert.throws(() => new UDer(Uint8Array.of(0x04, 0x05, 0x00)).octets(), RangeError);
  assert.throws(() => new UDer(Uint8Array.of(0x04, 0x84, 0, 0, 0, 1, 0)).octets(), RangeError);
  assert.throws(() => new UDer(Uint8Array.of(0x02, 0x01, 0x80)).integer(), RangeError);
  assert.throws(() => new UDer(Uint8Array.of(0x03, 0x02, 0x01, 0x00)).bits(), RangeError);
});

/** Reads a plain Ed25519 section: check integers, type, public key, pair, comment and padding. */
function ed25519Of(section) {
  const reader = new UWire(section);
  return {
    checks: [reader.uint32(), reader.uint32()],
    type: reader.text(),
    x: reader.string(),
    pair: reader.string(),
    comment: reader.text(),
    padding: reader.bytes(reader.remaining()),
  };
}

/** Writes a plain Ed25519 section from its parts. */
function ed25519({ checks, type, x, pair, comment, padding }) {
  const strings = [type, x, pair, comment].map((part) => UWire.string(part));
  return UWire.concat(...checks.map((check) => UWire.uint32(check)), ...strings, padding);
}

/** Reads the strings of a public blob. */
function blobOf(base64) {
  const reader = new UWire(UWire.decode64(base64));
  const strings = [];
  while (reader.remaining() > 0) strings.push(reader.string());
  return strings;
}

/** Writes a DER INTEGER of a small number. */
function integer(value) {
  return UDer.write(UDer.INTEGER, Uint8Array.of(value));
}

/** Writes the AlgorithmIdentifier SEQUENCE of dotted identifiers. */
function algorithmOf(...identifiers) {
  const der = new UDer(UDer.pkcs8(identifiers, new Uint8Array(0)));
  const info = der.sequence();
  info.integer();
  return UDer.write(UDer.SEQUENCE, info.element(UDer.SEQUENCE));
}

/** Runs a function with globalThis.crypto replaced. */
async function withCrypto(crypto, run) {
  const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  Object.defineProperty(globalThis, 'crypto', { value: crypto, configurable: true, writable: true });
  try {
    return await run();
  } finally {
    Object.defineProperty(globalThis, 'crypto', original);
  }
}

const isZero = (bytes) => bytes.every((byte) => byte === 0);

test('key: a plain OpenSSH section is read with any padding 1, 2, 3, … and refused malformed otherwise', async () => {
  const entry = keys.find((candidate) => candidate.name === 'Ed25519 OpenSSH');
  const parts = opensshOf(entry.text);
  const section = ed25519Of(parts.section);
  const count = (length) => Uint8Array.from({ length: length }, (_, index) => index + 1);
  const flipped = section.pair.slice();
  flipped[63] ^= 1;
  const cases = [
    ['loaded', { padding: count(7) }],
    ['loaded', { padding: count(0) }],
    ['malformed', { checks: [section.checks[0], section.checks[0] + 1] }],
    ['malformed', { padding: Uint8Array.of(1, 2, 4) }],
    ['malformed', { padding: Uint8Array.of(0) }],
    ['malformed', { pair: section.pair.subarray(0, 63) }],
    ['malformed', { pair: flipped }],
  ];
  for (const [code, change] of cases) {
    const text = openssh({ ...parts, section: ed25519({ ...section, ...change }) });
    assert.equal(await judge(text, ''), code, JSON.stringify(change, (name, value) => value?.length ?? value));
  }
  const text = openssh({ ...parts, section: ed25519({ ...section, padding: count(7) }) });
  const key = await UKey.inspect(encode(text), 'id');
  assert.equal(key.comment, 'user01@example.test');
  key.discard();
});

test('key: an OpenSSH file of another magic, with trailing bytes, no key or a public blob that does not read is '
  + 'refused',
  async () => {
    const entry = keys.find((candidate) => candidate.name === 'Ed25519 OpenSSH');
    const parts = opensshOf(entry.text);
    const [, x] = blobOf(entry.blob);
    const p256 = keys.find((candidate) => candidate.name === 'ECDSA P-256 OpenSSH');
    const [, , point] = blobOf(p256.blob);
    const header = (...strings) => UWire.concat(...strings.map((part) => UWire.string(part)));
    const malformedPoint = point.slice();
    malformedPoint[0] = 2;
    const cases = [
      ['malformed', { magic: encode('openssh-key-v2\0') }],
      ['malformed', { trailer: Uint8Array.of(0) }],
      ['several-keys', { count: 0 }],
      ['malformed', { header: UWire.concat(parts.header, Uint8Array.of(0)) }],
      ['malformed', { header: header('ssh-ed25519', x.subarray(0, 31)) }],
      ['malformed', { header: header('ssh-ed448', x) }],
      ['curve', { header: header('ecdsa-sha2-nistp224', 'nistp224', point) }],
      ['malformed', { header: header('ecdsa-sha2-nistp256', 'nistp384', point) }],
      ['malformed', { header: header('ecdsa-sha2-nistp256', 'nistp256', point.subarray(0, 64)) }],
      ['malformed', { header: header('ecdsa-sha2-nistp256', 'nistp256', malformedPoint) }],
      ['malformed', { header: header('ecdsa-sha2-nistp256', 'nistp256', point) }],
    ];
    for (const [code, change] of cases) {
      assert.equal(await judge(openssh({ ...parts, ...change }), ''), code, Object.keys(change).join());
    }
  });

test('key: an OpenSSH ECDSA private number longer than its curve is refused malformed', async () => {
  const entry = keys.find((candidate) => candidate.name === 'ECDSA P-256 OpenSSH');
  const parts = opensshOf(entry.text);
  const reader = new UWire(parts.section);
  const head = reader.bytes(8);
  const [type, curve, point] = [reader.string(), reader.string(), reader.string()];
  reader.mpint();
  const tail = reader.bytes(reader.remaining());
  const write = (d) => openssh({
    ...parts,
    section: UWire.concat(head, ...[type, curve, point].map((part) => UWire.string(part)), UWire.mpint(d), tail),
  });
  const long = new Uint8Array(33).fill(1);
  assert.equal(await judge(write(long), ''), 'malformed');
});

test('key: an encrypted OpenSSH file is refused for a cipher or kdf alone, another cipher or kdf, and bad kdf options',
  async () => {
    const entry = keys.find((candidate) => candidate.name === 'Ed25519 OpenSSH aes256-ctr');
    const parts = opensshOf(entry.text);
    const salt = new UWire(parts.options).string();
    const options = (...bytes) => UWire.concat(...bytes);
    const cases = [
      ['malformed', { cipher: 'none' }],
      ['malformed', { kdf: 'none' }],
      ['cipher', { cipher: 'aes256-cbc' }],
      ['kdf', { kdf: 'scrypt' }],
      ['malformed', { options: options(UWire.string(new Uint8Array(0)), UWire.uint32(16)) }],
      ['malformed', { options: options(UWire.string(salt), UWire.uint32(0)) }],
      ['malformed', { options: options(UWire.string(salt), UWire.uint32(16), Uint8Array.of(0)) }],
      ['passphrase', { options: options(UWire.string(salt), UWire.uint32(1)) }],
    ];
    for (const [code, change] of cases) {
      assert.equal(await judge(openssh({ ...parts, ...change }), entry.passphrase), code, JSON.stringify(change));
    }
  });

test('key: an armour without its closing dashes, a label out of A-Z0-9 or over 64 characters is not a key',
  async () => {
    const body = UWire.encode64(Uint8Array.of(1, 2, 3));
    const publicLabel = (length) => `${'X'.repeat(length - 'PUBLIC KEY'.length - 1)} PUBLIC KEY`;
    const cases = [
      [`-----BEGIN OPENSSH PRIVATE KEY\n${body}\n`, 'not-a-key'],
      [armour('openssh private key', Uint8Array.of(1)), 'not-a-key'],
      [armour('', Uint8Array.of(1)), 'not-a-key'],
      [armour(publicLabel(64), Uint8Array.of(1)), 'public-key'],
      [armour(publicLabel(65), Uint8Array.of(1)), 'not-a-key'],
      [armour('RSA PRIVATE KEY', Uint8Array.of(1, 2, 3)).replace('END RSA', 'END'), 'malformed'],
    ];
    for (const [text, code] of cases) assert.equal(await judge(text, ''), code, text);
  });

test('key: a text that is not armoured is a PuTTY key or a public key line only from its first non-space character',
  async () => {
    const putty = refusals.find((entry) => entry.refusal === 'putty').text;
    const line = refusals.find((entry) => entry.refusal === 'public-key' && !entry.text.startsWith('-----')).text;
    const blob = line.split(' ')[1];
    const cases = [
      [` \t\r\n${putty}`, 'putty'],
      [`user01 ${putty}`, 'not-a-key'],
      [`\n\n  ${line}`, 'public-key'],
      [`ecdsa-sha2-nistp256 ${blob}`, 'public-key'],
      [`sk-ssh-ed25519@openssh.com\t${blob}`, 'public-key'],
      [`ssh-ed25519 ${blob.slice(4)}`, 'not-a-key'],
      [`rsa-ssh ${blob}`, 'not-a-key'],
      ['', 'not-a-key'],
      ['  ', 'not-a-key'],
    ];
    for (const [text, code] of cases) assert.equal(await judge(text, ''), code, JSON.stringify(text));
  });

test('key: a PKCS #8 key of version 1 is read with its attributes and public key, which give the blob at once',
  async () => {
    const entry = keys.find((candidate) => candidate.name === 'Ed25519 PKCS #8');
    const body = bodyOf(entry.text);
    const seed = body.slice(-32);
    const [, x] = blobOf(entry.blob);
    const algorithm = algorithmOf('1.3.101.112');
    const key = UDer.write(UDer.OCTET_STRING, UDer.write(UDer.OCTET_STRING, seed));
    const attributes = UDer.write(UDer.EXPLICIT_0, UDer.write(UDer.SEQUENCE));
    const publicKey = UDer.write(UDer.IMPLICIT_1, Uint8Array.of(0), x);
    const write = (...parts) => armour('PRIVATE KEY', UDer.write(UDer.SEQUENCE, ...parts));
    for (const text of [write(integer(1), algorithm, key, attributes, publicKey), write(integer(1), algorithm, key,
      publicKey)]) {
      const inspected = await UKey.inspect(encode(text), entry.name);
      assert.equal(UWire.encode64(inspected.blob), entry.blob);
      assert.equal(inspected.fingerprint, entry.fingerprint);
      const loaded = await inspected.unlock(new Uint8Array(0), nothing);
      assert.equal(loaded.fingerprint, entry.fingerprint);
    }
    const cases = [
      write(integer(2), algorithm, key),
      write(UDer.write(UDer.INTEGER, Uint8Array.of(1, 0)), algorithm, key),
      write(integer(0), algorithm, key, integer(0)),
      armour('PRIVATE KEY', UWire.concat(bodyOf(write(integer(0), algorithm, key)), Uint8Array.of(0))),
      write(integer(0), algorithm, UDer.write(UDer.OCTET_STRING, UDer.write(UDer.OCTET_STRING, seed), integer(0))),
    ];
    for (const text of cases) assert.equal(await judge(text, ''), 'malformed', text);
  });

test('key: a PKCS #1 key of another version or with a number past the eight is refused, a zero modulus rsa-size',
  async () => {
    const n = new Uint8Array(256).fill(0x7f);
    const numbers = (count) => Array.from({ length: count }, () => integer(3));
    const write = (version, modulus, count) => armour('RSA PRIVATE KEY',
      UDer.write(UDer.SEQUENCE, integer(version), UDer.write(UDer.INTEGER, modulus), ...numbers(count)));
    assert.equal((await UKey.inspect(encode(write(0, n, 7)), 'id_rsa')).kind, 'RSA 2047');
    assert.equal(await judge(write(1, n, 7), ''), 'malformed');
    assert.equal(await judge(write(0, n, 8), ''), 'malformed');
    assert.equal(await judge(write(0, Uint8Array.of(0), 7), ''), 'rsa-size');
  });

test('key: an OpenSSH RSA key whose prime is 1 is refused malformed at unlock and discarded', async (t) => {
  const entry = keys.find((candidate) => candidate.name === 'RSA 1024 OpenSSH');
  const parts = opensshOf(entry.text);
  const reader = new UWire(parts.section);
  const head = reader.bytes(8);
  const type = reader.string();
  const [n, e, d, qi, , q] = Array.from({ length: 6 }, () => reader.mpint());
  const tail = reader.bytes(reader.remaining());
  const numbers = [n, e, d, qi, Uint8Array.of(1), q].map((number) => UWire.mpint(number));
  const text = openssh({ ...parts, section: UWire.concat(head, UWire.string(type), ...numbers, tail) });
  const decode = t.mock.method(UWire, 'decode64');
  const key = await UKey.inspect(encode(text), entry.name);
  const body = decode.mock.calls[0].result;
  await assert.rejects(key.unlock(new Uint8Array(0), nothing), { code: 'malformed' });
  assert.ok(isZero(body));
  await assert.rejects(key.unlock(new Uint8Array(0), nothing), { code: 'malformed' });
});

test('key: a SEC1 key of another version, without a curve or with one the PKCS #8 algorithm does not name is refused',
  async () => {
    const entry = keys.find((candidate) => candidate.name === 'ECDSA P-256 SEC1 without its public key');
    const reader = new UDer(bodyOf(entry.text)).sequence();
    reader.integer();
    const d = reader.octets().slice();
    const p256 = UDer.write(UDer.EXPLICIT_0, algorithmOf('1.2.840.10045.3.1.7').subarray(2));
    const p384 = UDer.write(UDer.EXPLICIT_0, algorithmOf('1.3.132.0.34').subarray(2));
    const sec1 = (version, scalar, ...parts) => UDer.write(UDer.SEQUENCE, integer(version),
      UDer.write(UDer.OCTET_STRING, scalar), ...parts);
    const pkcs8 = (inner) => armour('PRIVATE KEY', UDer.pkcs8(['1.2.840.10045.2.1', '1.2.840.10045.3.1.7'], inner));
    const cases = [
      armour('EC PRIVATE KEY', sec1(0, d, p256)),
      armour('EC PRIVATE KEY', sec1(2, d, p256)),
      armour('EC PRIVATE KEY', UDer.write(UDer.SEQUENCE, UDer.write(UDer.INTEGER, Uint8Array.of(1, 1)),
        UDer.write(UDer.OCTET_STRING, d), p256)),
      armour('EC PRIVATE KEY', sec1(1, d)),
      armour('EC PRIVATE KEY', sec1(1, d, p256, integer(0))),
      pkcs8(sec1(1, d, p384)),
    ];
    for (const text of cases) assert.equal(await judge(text, ''), 'malformed', text);
    for (const text of [armour('EC PRIVATE KEY', sec1(1, UWire.concat(Uint8Array.of(0), d), p256)),
      pkcs8(sec1(1, d, p256))]) {
      const key = await UKey.inspect(encode(text), entry.name);
      const loaded = await key.unlock(new Uint8Array(0), nothing);
      assert.equal(loaded.fingerprint, entry.fingerprint);
    }
  });

test('key: without WebCrypto every kind is refused unsupported, naming the kind, and its bytes are zero', async (t) => {
  const texts = new Map([
    ['ED25519', 'Ed25519'],
    ['ECDSA P-256', 'ECDSA P-256'],
    ['ECDSA P-384', 'ECDSA P-384'],
    ['ECDSA P-521', 'ECDSA P-521'],
    ['RSA 1024', 'RSA'],
  ]);
  const decode = t.mock.method(UWire, 'decode64');
  for (const crypto of [undefined, {}]) {
    for (const [kind, name] of texts) {
      const entry = keys.find((candidate) => candidate.kind === kind);
      const bytes = encode(entry.text);
      await withCrypto(crypto, async () => {
        await assert.rejects(UKey.inspect(bytes, entry.name), {
          code: 'unsupported',
          text: `This browser cannot sign with ${name} keys.`,
          command: null,
        });
      });
      assert.ok(isZero(bytes), kind);
      assert.ok(isZero(decode.mock.calls.at(-1).result), kind);
    }
  }
});

test('key: the PEM body, the bcrypt output, the decrypted section and every number given to WebCrypto are zero '
  + 'afterwards',
  async (t) => {
    const subtle = globalThis.crypto.subtle;
    const spies = [
      t.mock.method(UWire, 'decode64'),
      t.mock.method(UWire, 'encodeUrl64'),
      t.mock.method(UBcrypt, 'pbkdf'),
      t.mock.method(UDer, 'pkcs8'),
      t.mock.method(subtle, 'decrypt'),
      t.mock.method(subtle, 'importKey'),
      t.mock.method(subtle, 'digest'),
    ];
    const [decode, url, pbkdf, pkcs8, decrypt, importKey, digest] = spies;
    const derived = (entry) => entry.name.endsWith(' without its public key') || entry.name === 'Ed25519 PKCS #8';
    for (const entry of keys.filter((candidate) => candidate.format === 'openssh' || derived(candidate))) {
      for (const spy of spies) spy.mock.resetCalls();
      const key = await UKey.inspect(encode(entry.text), entry.name);
      const bodies = decode.mock.calls.map((call) => call.result);
      await key.unlock(encode(entry.passphrase), nothing);
      const sha512 = digest.mock.calls.filter((call) => call.arguments[0] === 'SHA-512');
      const held = [
        ...bodies,
        ...pkcs8.mock.calls.flatMap((call) => [call.arguments[1], call.result]),
        ...importKey.mock.calls.filter((call) => call.arguments[0] !== 'jwk').map((call) => call.arguments[1]),
        ...decrypt.mock.calls.flatMap((call) => [call.arguments[0].counter, call.arguments[2]]),
        ...sha512.map((call) => call.arguments[1]),
      ];
      const calls = [...pbkdf.mock.calls, ...decrypt.mock.calls, ...sha512];
      const results = await Promise.all(calls.map((call) => call.result));
      held.push(...results.map((result) => (result instanceof ArrayBuffer ? new Uint8Array(result) : result)));
      if (entry.format === 'openssh') held.push(...url.mock.calls.map((call) => call.arguments[0]));
      for (const bytes of held) assert.ok(isZero(bytes), entry.name);
      assert.equal(decrypt.mock.callCount(), entry.cipher === 'none' ? 0 : 1, entry.name);
      for (const call of importKey.mock.calls) {
        assert.equal(call.arguments[3], call.arguments[0] === 'pkcs8', entry.name);
      }
      assert.equal(pkcs8.mock.callCount(), entry.name === 'Ed25519 PKCS #8' ? 1 : 0, entry.name);
    }
  });

test('key: the DER reader refuses an empty identifier, one cut in an arc, trailing bytes and a missing length', () => {
  assert.throws(() => new UDer(Uint8Array.of(0x06, 0x00)).oid(), RangeError);
  assert.throws(() => new UDer(Uint8Array.of(0x06, 0x02, 0x2a, 0x86)).oid(), RangeError);
  assert.throws(() => new UDer(Uint8Array.of(0x05, 0x00)).end(), RangeError);
  assert.throws(() => new UDer(Uint8Array.of(0x04)).octets(), RangeError);
  assert.throws(() => new UDer(Uint8Array.of(0x04, 0x80)).octets(), RangeError);
  assert.throws(() => new UDer(Uint8Array.of(0x04, 0x82, 0x01)).octets(), RangeError);
  assert.throws(() => new UDer(Uint8Array.of(0x02, 0x00)).integer(), RangeError);
  assert.throws(() => new UDer(Uint8Array.of(0x03, 0x00)).bits(), RangeError);
  assert.throws(() => new UDer(new Uint8Array(0)).octets(), RangeError);
  const empty = new UDer(new Uint8Array(0));
  assert.equal(empty.next(UDer.SEQUENCE), false);
  empty.end();
});

test('key: the DER reader reads the long length forms, an integer without its leading zeros and an implicit bit string',
  () => {
    const long = new UDer(UWire.concat(Uint8Array.of(0x04, 0x81, 0x80), new Uint8Array(0x80).fill(1),
      Uint8Array.of(0x04, 0x82, 0x01, 0x00), new Uint8Array(0x100).fill(2)));
    assert.deepEqual(long.octets(), new Uint8Array(0x80).fill(1));
    assert.ok(long.next(UDer.OCTET_STRING));
    assert.deepEqual(long.octets(), new Uint8Array(0x100).fill(2));
    long.end();
    assert.deepEqual([...new UDer(Uint8Array.of(0x02, 0x03, 0x00, 0x00, 0x05)).integer()], [5]);
    assert.deepEqual([...new UDer(Uint8Array.of(0x02, 0x01, 0x00)).integer()], []);
    assert.deepEqual([...new UDer(Uint8Array.of(0x81, 0x03, 0x00, 0x09, 0x08)).bits(UDer.IMPLICIT_1)], [9, 8]);
    assert.equal(new UDer(Uint8Array.of(0x04, 0x00)).next(UDer.SEQUENCE), false);
  });

test('key: the DER writer uses the short form below 128 bytes, then one and two length bytes', () => {
  const header = (length) => [...UDer.write(UDer.OCTET_STRING, new Uint8Array(length)).subarray(0, 4)];
  assert.deepEqual(header(0x7f).slice(0, 2), [0x04, 0x7f]);
  assert.deepEqual(header(0x80).slice(0, 3), [0x04, 0x81, 0x80]);
  assert.deepEqual(header(0xff).slice(0, 3), [0x04, 0x81, 0xff]);
  assert.deepEqual(header(0x100), [0x04, 0x82, 0x01, 0x00]);
  assert.deepEqual(header(0x1234), [0x04, 0x82, 0x12, 0x34]);
  assert.deepEqual([...UDer.write(UDer.SEQUENCE, Uint8Array.of(1), Uint8Array.of(2, 3))], [0x30, 0x03, 1, 2, 3]);
});

test('key: the DER identifiers are written in base 128 with the first two arcs joined and read back', () => {
  const identifiers = ['1.2.840.113549.1.1.1', '2.999.3', '0.39', '1.3.101.112'];
  const der = UDer.pkcs8(identifiers, new Uint8Array(0));
  const info = new UDer(der).sequence();
  info.integer();
  const algorithm = info.sequence();
  const first = algorithm.element(UDer.OID);
  assert.equal(Buffer.from(first).toString('hex'), '2a864886f70d010101');
  assert.equal(new UDer(algorithmOf('2.999.3').subarray(2)).oid(), '2.999.3');
  for (const identifier of identifiers.slice(1)) assert.equal(algorithm.oid(), identifier);
  algorithm.end();
});

test('key: the PKCS #8 writer overwrites the OCTET STRING it builds around the key', (t) => {
  const write = t.mock.method(UDer, 'write');
  const der = UDer.pkcs8(['1.3.101.112'], Uint8Array.of(9, 9));
  const octets = write.mock.calls.find((call) => call.arguments[0] === UDer.OCTET_STRING).result;
  assert.ok(isZero(octets));
  assert.deepEqual([...der.subarray(-4)], [0x04, 0x02, 9, 9]);
});

test('key: the DER reader refuses the indefinite length even with bytes after it, and reads a length of three bytes',
  () => {
    const indefinite = UWire.concat(Uint8Array.of(0x04, 0x80), new Uint8Array(0x80));
    assert.throws(() => new UDer(indefinite).octets(), { message: 'der: invalid length' });
    const three = new UDer(UWire.concat(Uint8Array.of(0x04, 0x83, 0x00, 0x01, 0x00), new Uint8Array(0x100).fill(3)));
    assert.deepEqual(three.octets(), new Uint8Array(0x100).fill(3));
    three.end();
  });

test('key: every refusal carries the text the page shows', () => {
  const texts = {
    'too-large': 'This file is over 16384 bytes, larger than any private key.',
    'not-a-key': 'This is not a private key.',
    'public-key': 'This is a public key; drop the private one.',
    dsa: 'DSA keys are not supported; make a new key.',
    putty: 'PuTTY keys are read once converted to OpenSSH.',
    'pem-encrypted': 'This key is encrypted in the old PEM format.',
    cipher: 'This key is encrypted with a cipher the page does not read.',
    kdf: 'This key is protected by a key derivation the page does not read.',
    rounds: 'This key asks more than 2048 bcrypt rounds.',
    'security-key': 'A hardware security key cannot sign in a browser.',
    'several-keys': 'This file holds several keys; drop a file with one.',
    curve: 'This curve is not supported; use Ed25519, P-256, P-384 or P-521.',
    'rsa-size': 'RSA keys sign here with 1024 to 16384 bits.',
    passphrase: 'Wrong passphrase.',
    malformed: 'This key does not read.',
  };
  const commands = new Set(['dsa', 'putty', 'pem-encrypted', 'cipher', 'kdf', 'rounds']);
  for (const [code, text] of Object.entries(texts)) {
    const refusal = new Refusal(code);
    assert.deepEqual([refusal.code, refusal.text, refusal.command === null], [code, text, !commands.has(code)]);
  }
});

test('key: signable without WebCrypto is false, and probes each kind once per subtle with a non-extractable key',
  async () => {
    assert.equal(await withCrypto(undefined, () => UKey.signable('ED25519')), false);
    const probes = [];
    const subtle = {
      generateKey: async (...args) => {
        probes.push(args);
        return {};
      },
    };
    const first = UKey.signable('ECDSA P-521', subtle);
    assert.equal(UKey.signable('ECDSA P-521', subtle), first);
    assert.equal(await first, true);
    assert.equal(await UKey.signable('ED25519', subtle), true);
    assert.equal(await UKey.signable('ED25519', subtle), true);
    assert.deepEqual(probes, [
      [{ name: 'ECDSA', namedCurve: 'P-521' }, false, ['sign']],
      [{ name: 'Ed25519' }, false, ['sign']],
    ]);
  });

test('key: an encrypted key whose section is not its public key is refused malformed at unlock and discarded',
  async (t) => {
    const entry = keys.find((candidate) => candidate.name === 'Ed25519 OpenSSH aes256-ctr');
    const parts = opensshOf(entry.text);
    const [type, x] = blobOf(entry.blob);
    const other = x.slice();
    other[0] ^= 1;
    const text = openssh({ ...parts, header: UWire.concat(UWire.string(type), UWire.string(other)) });
    const decode = t.mock.method(UWire, 'decode64');
    const key = await UKey.inspect(encode(text), entry.name);
    const body = decode.mock.calls[0].result;
    await assert.rejects(key.unlock(encode(entry.passphrase), nothing), { code: 'malformed' });
    assert.ok(isZero(body));
  });

test('key: an empty passphrase is refused before bcrypt runs', async () => {
  const entry = keys.find((candidate) => candidate.name === 'Ed25519 OpenSSH aes128-ctr');
  const key = await UKey.inspect(encode(entry.text), entry.name);
  const rounds = [];
  await assert.rejects(key.unlock(new Uint8Array(0), (round) => rounds.push(round)), { code: 'passphrase' });
  assert.deepEqual(rounds, []);
  key.discard();
});

test('key: an armour is read only between its own BEGIN and END lines, Proc-Type anywhere inside it', async () => {
  const entry = keys.find((candidate) => candidate.name === 'RSA 1024 PKCS #1');
  const lines = entry.text.split('\n');
  const body = lines.slice(1, -2).join('\n');
  const cases = [
    ['-----BEGIN PUBLIC KEYX', 'not-a-key'],
    ['-----BEGIN DSA PRIVATE KEYX', 'not-a-key'],
    [`${lines[0]}\n${body}\n`, 'malformed'],
    [`${lines[0]}Proc-Type: 4,ENCRYPTED\n${body}\n${lines.at(-2)}\n`, 'pem-encrypted'],
    [`${lines[0]}\n${body}\n${lines.at(-2)}`, 'loaded'],
  ];
  for (const [text, code] of cases) assert.equal(await judge(text, ''), code, text.slice(0, 40));
});

test('key: a public key line is recognised from its first characters, with any run of spaces before its base64',
  async () => {
    const cases = [
      ['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5', 'public-key'],
      ['ssh-ed25519  \tAAAAC3NzaC1lZDI1NTE5AAAAIA== user01@example.test', 'public-key'],
      ['user01 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5', 'not-a-key'],
      ['PuTTY-User-Key-File-', 'putty'],
    ];
    for (const [text, code] of cases) assert.equal(await judge(text, ''), code, text);
  });

test('key: an OpenSSH file with a cipher and no kdf, or a kdf and no cipher, is malformed even over a plain section',
  async () => {
    const parts = opensshOf(keys.find((candidate) => candidate.name === 'Ed25519 OpenSSH').text);
    for (const change of [{ cipher: 'aes256-ctr' }, { kdf: 'bcrypt' }]) {
      assert.equal(await judge(openssh({ ...parts, ...change }), 'passphrase-01'), 'malformed', JSON.stringify(change));
    }
  });

test('key: bytes after the outer SEQUENCE of a PKCS #1 or SEC1 key are refused', async () => {
  for (const name of ['RSA 1024 PKCS #1', 'ECDSA P-256 SEC1']) {
    const entry = keys.find((candidate) => candidate.name === name);
    const label = entry.format === 'pkcs1' ? 'RSA PRIVATE KEY' : 'EC PRIVATE KEY';
    assert.equal(await judge(armour(label, UWire.concat(bodyOf(entry.text), Uint8Array.of(0x05, 0x00))), ''),
      'malformed', name);
  }
});

test('key: a SEC1 key of P-384 inside a PKCS #8 key of P-256 is refused malformed', async () => {
  const entry = keys.find((candidate) => candidate.name === 'ECDSA P-384 SEC1 without its public key');
  const inner = bodyOf(entry.text);
  const text = armour('PRIVATE KEY', UDer.pkcs8(['1.2.840.10045.2.1', '1.2.840.10045.3.1.7'], inner));
  assert.equal(await judge(text, ''), 'malformed');
  const own = armour('PRIVATE KEY', UDer.pkcs8(['1.2.840.10045.2.1', '1.3.132.0.34'], inner));
  assert.equal(await judge(own, ''), 'loaded');
});

test('key: inspect refuses at once an Ed25519 part, an EC point or an EC private number of the wrong size',
  async () => {
    const ed25519 = keys.find((candidate) => candidate.name === 'Ed25519 PKCS #8');
    const seed = bodyOf(ed25519.text).slice(-32);
    const [, x] = blobOf(ed25519.blob);
    const algorithm = algorithmOf('1.3.101.112');
    const inner = (bytes) => UDer.write(UDer.OCTET_STRING, UDer.write(UDer.OCTET_STRING, bytes));
    const v1 = (bytes, publicKey) => armour('PRIVATE KEY', UDer.write(UDer.SEQUENCE, integer(1), algorithm,
      inner(bytes), UDer.write(UDer.IMPLICIT_1, Uint8Array.of(0), publicKey)));
    const p256 = keys.find((candidate) => candidate.name === 'ECDSA P-256 SEC1');
    const [, , point] = blobOf(p256.blob);
    const reader = new UDer(bodyOf(p256.text)).sequence();
    reader.integer();
    const d = reader.octets().slice();
    const curve = UDer.write(UDer.EXPLICIT_0, algorithmOf('1.2.840.10045.3.1.7').subarray(2));
    const sec1 = (scalar, bits) => armour('EC PRIVATE KEY', UDer.write(UDer.SEQUENCE, integer(1),
      UDer.write(UDer.OCTET_STRING, scalar), curve, UDer.write(UDer.EXPLICIT_1, UDer.write(UDer.BIT_STRING,
        Uint8Array.of(0), bits))));
    const compressed = point.slice();
    compressed[0] = 2;
    const cases = [
      v1(seed.subarray(0, 31), x),
      v1(seed, x.subarray(0, 31)),
      sec1(d, point.subarray(0, 64)),
      sec1(d, compressed),
      sec1(UWire.concat(Uint8Array.of(1), d), point),
    ];
    for (const text of cases) await assert.rejects(UKey.inspect(encode(text), 'id'), { code: 'malformed' }, text);
    const key = await UKey.inspect(encode(sec1(UWire.concat(Uint8Array.of(0), d), point)), 'id');
    assert.equal(key.fingerprint, p256.fingerprint);
    key.discard();
  });

test('key: an OpenSSH RSA key gives WebCrypto the JWK of the same key in PKCS #1, its dp and dq computed',
  async (t) => {
    const importKey = t.mock.method(globalThis.crypto.subtle, 'importKey');
    for (const bits of [1024, 2048, 4096]) {
      const jwks = [];
      for (const name of [`RSA ${bits} OpenSSH`, `RSA ${bits} PKCS #1`]) {
        importKey.mock.resetCalls();
        const entry = keys.find((candidate) => candidate.name === name);
        await (await UKey.inspect(encode(entry.text), name)).unlock(new Uint8Array(0), nothing);
        jwks.push(importKey.mock.calls[0].arguments[1]);
      }
      assert.deepEqual(jwks[0], jwks[1], String(bits));
      assert.deepEqual(Object.keys(jwks[0]).sort(), ['d', 'dp', 'dq', 'e', 'kty', 'n', 'p', 'q', 'qi']);
    }
  });

test('key: the DER reader names each fault in its error', () => {
  const cases = [
    [() => new UDer(Uint8Array.of(0x04, 0x00)).sequence(), 'der: unexpected tag'],
    [() => new UDer(Uint8Array.of(0x04, 0x02, 0x00)).octets(), 'der: short input'],
    [() => new UDer(Uint8Array.of(0x04)).octets(), 'der: short input'],
    [() => new UDer(Uint8Array.of(0x04, 0x80)).octets(), 'der: invalid length'],
    [() => new UDer(Uint8Array.of(0x02, 0x00)).integer(), 'der: invalid integer'],
    [() => new UDer(Uint8Array.of(0x03, 0x00)).bits(), 'der: invalid bit string'],
    [() => new UDer(Uint8Array.of(0x06, 0x00)).oid(), 'der: invalid identifier'],
    [() => new UDer(Uint8Array.of(0x05, 0x00)).end(), 'der: trailing bytes'],
  ];
  for (const [read, message] of cases) assert.throws(read, { name: 'RangeError', message: message });
  assert.deepEqual([...new UDer(Uint8Array.of(0x04, 0x81, 0x00)).octets()], []);
});

test('key: the PEM body of every refused key is zero afterwards', async (t) => {
  const decode = t.mock.method(UWire, 'decode64');
  const unknown = armour('PRIVATE KEY', UDer.pkcs8(['1.3.101.113'], UDer.write(UDer.OCTET_STRING, new Uint8Array(57))));
  const ed25519 = opensshOf(keys.find((candidate) => candidate.name === 'Ed25519 OpenSSH').text);
  const inspected = refusals.filter((entry) => entry.refusal !== 'passphrase').map((entry) => entry.text);
  let bodies = 0;
  for (const text of [...inspected, unknown, openssh({ ...ed25519, count: 2 })]) {
    decode.mock.resetCalls();
    await assert.rejects(UKey.inspect(encode(text), 'id'), Refusal);
    for (const call of decode.mock.calls) assert.ok(isZero(call.result), text.slice(0, 60));
    bodies += decode.mock.callCount();
  }
  assert.ok(bodies > inspected.length / 2);
});

test('key: bcrypt pbkdf overwrites the digests of its passphrase and salts and every block input it hashed',
  async (t) => {
    const digest = t.mock.method(globalThis.crypto.subtle, 'digest');
    const passphrase = encode('passphrase-01');
    const key = await UBcrypt.pbkdf(passphrase, encode('salt-01'), 3, 48, nothing);
    assert.equal(key.length, 48);
    assert.equal(digest.mock.callCount(), 1 + 3 * 2);
    for (const call of digest.mock.calls) {
      assert.equal(call.arguments[0], 'SHA-512');
      if (call.arguments[1] !== passphrase) assert.ok(isZero(call.arguments[1]));
      assert.ok(isZero(new Uint8Array(await call.result)));
    }
  });

test('key: an EC key without its point, in SEC1 or PKCS #8, is imported by JWK with d·G on each curve', async (t) => {
  const importKey = t.mock.method(globalThis.crypto.subtle, 'importKey');
  const curves = new Map([
    ['ECDSA P-256', '1.2.840.10045.3.1.7'],
    ['ECDSA P-384', '1.3.132.0.34'],
    ['ECDSA P-521', '1.3.132.0.35'],
  ]);
  const entries = keys.filter((candidate) => candidate.name.endsWith(' without its public key'));
  assert.deepEqual(entries.map((entry) => entry.kind), [...curves.keys()]);
  for (const entry of entries) {
    const [, , point] = blobOf(entry.blob);
    const size = (point.length - 1) / 2;
    const jwk = [UWire.encodeUrl64(point.subarray(1, 1 + size)), UWire.encodeUrl64(point.subarray(1 + size))];
    const pkcs8 = armour('PRIVATE KEY', UDer.pkcs8(['1.2.840.10045.2.1', curves.get(entry.kind)], bodyOf(entry.text)));
    for (const text of [entry.text, pkcs8]) {
      importKey.mock.resetCalls();
      const key = await UKey.inspect(encode(text), entry.name);
      assert.equal(key.blob, undefined, entry.name);
      const loaded = await key.unlock(new Uint8Array(0), nothing);
      assert.equal(UWire.encode64(loaded.blob), entry.blob, entry.name);
      assert.equal(loaded.fingerprint, entry.fingerprint, entry.name);
      const imports = importKey.mock.calls.map((call) => [call.arguments[0], call.arguments[1].x, call.arguments[1].y]);
      assert.deepEqual(imports, [['jwk', ...jwk]], entry.name);
    }
  }
});

test('key: the EC point of d = 1 is the generator and of d = n - 1 its opposite, and d = 0 or n is refused',
  async (t) => {
    const importKey = t.mock.method(globalThis.crypto.subtle, 'importKey');
    const curves = [
      ['1.2.840.10045.3.1.7', 32, 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'],
      ['1.3.132.0.34', 48, `${'ff'.repeat(24)}c7634d81f4372ddf581a0db248b0a77aecec196accc52973`],
      ['1.3.132.0.35', 66, `01${'ff'.repeat(32)}fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409`],
    ];
    for (const [identifier, size, order] of curves) {
      const n = BigInt(`0x${order}`);
      const sec1 = (d) => UDer.write(UDer.SEQUENCE, integer(1),
        UDer.write(UDer.OCTET_STRING, Buffer.from(d.toString(16).padStart(2 * size, '0'), 'hex')),
        UDer.write(UDer.EXPLICIT_0, algorithmOf(identifier).subarray(2)));
      for (const d of [1n, n - 1n]) {
        const der = Buffer.from(sec1(d));
        const want = createPrivateKey({ key: der, format: 'der', type: 'sec1' }).export({ format: 'jwk' });
        const key = await UKey.inspect(encode(armour('EC PRIVATE KEY', der)), identifier);
        const [, , point] = blobOf(UWire.encode64((await key.unlock(new Uint8Array(0), nothing)).blob));
        const [x, y] = [point.subarray(1, 1 + size), point.subarray(1 + size)].map((half) => UWire.encodeUrl64(half));
        assert.deepEqual([point[0], x, y], [4, want.x, want.y], `${identifier} ${d}`);
      }
      for (const d of [0n, n]) {
        importKey.mock.resetCalls();
        assert.equal(await judge(armour('EC PRIVATE KEY', sec1(d)), ''), 'malformed', `${identifier} ${d}`);
        assert.equal(importKey.mock.callCount(), 0, `${identifier} ${d}`);
      }
    }
  });

test('key: an OpenSSH comment that is not UTF-8 reads with U+FFFD for its invalid bytes, and the key loads',
  async () => {
    const entry = keys.find((candidate) => candidate.name === 'Ed25519 OpenSSH Latin-1 comment');
    const key = await UKey.inspect(encode(entry.text), entry.name);
    assert.equal(key.comment, 'user01@example.test caf\ufffd\ufffd');
    const loaded = await key.unlock(new Uint8Array(0), nothing);
    assert.equal(loaded.fingerprint, entry.fingerprint);
  });

test('key: no array the DER and wire writers build while a key is imported still holds its private number',
  async (t) => {
    const spies = [[UDer, 'write'], [UWire, 'concat'], [UWire, 'string'], [UWire, 'mpint']].map(([owner, name]) =>
      t.mock.method(owner, name));
    for (const entry of keys.filter((candidate) => candidate.format !== 'openssh')) {
      const d = Buffer.from(createPrivateKey(entry.text).export({ format: 'jwk' }).d, 'base64url').subarray(-16);
      for (const spy of spies) spy.mock.resetCalls();
      await (await UKey.inspect(encode(entry.text), entry.name)).unlock(new Uint8Array(0), nothing);
      const built = spies.flatMap((spy) => spy.mock.calls.map((call) => Buffer.from(call.result)));
      assert.ok(built.length > 0, entry.name);
      for (const bytes of built) assert.equal(bytes.includes(d), false, entry.name);
    }
  });

test('key: bcrypt pbkdf overwrites its block inputs and outputs and the Blowfish state of every hash', async (t) => {
  const lists = [];
  const from = Array.from;
  t.mock.method(Array, 'from', (...args) => {
    const list = from(...args);
    lists.push(list);
    return list;
  });
  const slices = t.mock.method(Uint32Array.prototype, 'slice');
  const made = [];
  const Native = Uint32Array;
  globalThis.Uint32Array = class extends Native {
    constructor(...args) {
      super(...args);
      made.push(this);
    }
  };
  try {
    await UBcrypt.pbkdf(encode('passphrase-01'), encode('salt-01'), 2, 48, nothing);
  } finally {
    globalThis.Uint32Array = Native;
  }
  assert.equal(lists.length, 2);
  const states = slices.mock.calls.map((call) => call.result);
  assert.equal(states.length, 2 * 2 * 3);
  const blocks = made.filter((words) => words.length === 2);
  assert.equal(blocks.length, 2 * 2 * 129);
  for (const words of [...lists.flat(), ...states, ...blocks]) assert.ok(isZero(words));
});
