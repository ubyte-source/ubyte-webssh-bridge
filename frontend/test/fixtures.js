import { createCipheriv, createHash, createHmac, generateKeyPairSync, randomBytes } from 'node:crypto';
import { UBcrypt } from '../public/javascript/bcrypt.js';

// The key files of the tests and the texts the page refuses, generated with node:crypto once a run; the SSH
// encodings are written here, apart from the page's own.
const comment = 'user01@example.test';
const passphrase = 'passphrase-01';
const kinds = ['ED25519', 'ECDSA P-256', 'ECDSA P-384', 'ECDSA P-521', 'RSA 1024', 'RSA 2048', 'RSA 4096'];
const ciphers = new Map([
  ['aes128-ctr', 16],
  ['aes192-ctr', 24],
  ['aes256-ctr', 32],
]);
// Few rounds keep the tests fast; the page reads every count up to 2048 alike.
const rounds = 4;
const families = new Map();
let refused;

/** Writes a big-endian uint32. */
function uint32(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
}

/** Writes an SSH string of bytes, or of a text in UTF-8. */
function string(value) {
  const bytes = Buffer.from(value);
  return Buffer.concat([uint32(bytes.length), bytes]);
}

/** Writes an SSH mpint of a big-endian magnitude. */
function mpint(magnitude) {
  let start = 0;
  while (start < magnitude.length && magnitude[start] === 0) start++;
  const value = magnitude.subarray(start);
  return string(value[0] >= 0x80 ? Buffer.concat([Buffer.of(0), value]) : value);
}

/** Writes a DER element shorter than 128 bytes. */
function der(tag, ...contents) {
  const body = Buffer.concat(contents);
  return Buffer.concat([Buffer.of(tag, body.length), body]);
}

/** Reads the contents of the DER elements that follow one another in bytes. */
function elements(bytes) {
  const contents = [];
  let at = 0;
  while (at < bytes.length) {
    let start = at + 2;
    let length = bytes[at + 1];
    if (length >= 0x80) {
      start += length - 0x80;
      length = bytes.subarray(at + 2, start).reduce((value, byte) => value * 256 + byte, 0);
    }
    contents.push(bytes.subarray(start, start + length));
    at = start + length;
  }
  return contents;
}

/** Writes a body in its armour, in lines of 70 characters for OpenSSH as ssh-keygen does, of 64 otherwise. */
function armour(label, body) {
  const width = label === 'OPENSSH PRIVATE KEY' ? 70 : 64;
  const lines = Buffer.from(body).toString('base64').match(new RegExp(`.{1,${width}}`, 'g'));
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

/** The SSH type of a key pair, its public blob from the public key and its private part in OpenSSH order. */
function sshOf({ publicKey, privateKey }) {
  const own = publicKey.export({ format: 'jwk' });
  const secret = privateKey.export({ format: 'jwk' });
  const bytes = (jwk, name) => Buffer.from(jwk[name], 'base64url');
  if (own.kty === 'OKP') {
    const blob = Buffer.concat([string('ssh-ed25519'), string(bytes(own, 'x'))]);
    const pair = Buffer.concat([bytes(secret, 'd'), bytes(own, 'x')]);
    return { type: 'ssh-ed25519', blob: blob, part: Buffer.concat([blob, string(pair)]) };
  }
  if (own.kty === 'EC') {
    const curve = `nistp${own.crv.slice(2)}`;
    const point = Buffer.concat([Buffer.of(4), bytes(own, 'x'), bytes(own, 'y')]);
    const blob = Buffer.concat([string(`ecdsa-sha2-${curve}`), string(curve), string(point)]);
    return { type: `ecdsa-sha2-${curve}`, blob: blob, part: Buffer.concat([blob, mpint(bytes(secret, 'd'))]) };
  }
  const numbers = ['n', 'e', 'd', 'qi', 'p', 'q'].map((name) => mpint(bytes(secret, name)));
  return {
    type: 'ssh-rsa',
    blob: Buffer.concat([string('ssh-rsa'), mpint(bytes(own, 'e')), mpint(bytes(own, 'n'))]),
    part: Buffer.concat([string('ssh-rsa'), ...numbers]),
  };
}

/** Writes a plain private section: check integers, each private part and its note, padding to the block. */
function plainSection(parts, block, note = comment) {
  const check = randomBytes(4);
  const plain = Buffer.concat([check, check, ...parts.flatMap((part) => [part, string(note)])]);
  const padding = Uint8Array.from({ length: (block - (plain.length % block)) % block }, (_, index) => index + 1);
  return Buffer.concat([plain, padding]);
}

/** Writes an openssh-key-v1 file; the tag of an AEAD cipher follows its section. */
function openssh({ cipher, kdf, options, blobs, section, tag = Buffer.alloc(0) }) {
  const head = [Buffer.from('openssh-key-v1\0'), string(cipher), string(kdf), string(options), uint32(blobs.length)];
  const body = Buffer.concat([...head, ...blobs.map((blob) => string(blob)), string(section), tag]);
  return armour('OPENSSH PRIVATE KEY', body);
}

/** The parts of a plain OpenSSH file of private parts and their public blobs. */
function plainParts(blobs, parts, note) {
  return { cipher: 'none', kdf: 'none', options: Buffer.alloc(0), blobs: blobs, section: plainSection(parts, 8, note) };
}

/** Derives bytes from the passphrase with bcrypt under a new salt; returns them with the kdf options. */
async function derive(length) {
  const salt = randomBytes(16);
  const derived = await UBcrypt.pbkdf(Buffer.from(passphrase), salt, rounds, length, () => {});
  return { options: Buffer.concat([string(salt), uint32(rounds)]), derived: derived };
}

/** The parts of the OpenSSH file of a key pair, plain for the cipher `none`, else under AES-CTR. */
async function opensshParts(pair, cipher, note) {
  const { blob, part } = sshOf(pair);
  if (cipher === 'none') return plainParts([blob], [part], note);
  const length = ciphers.get(cipher);
  const { options, derived } = await derive(length + 16);
  const aes = createCipheriv(`aes-${8 * length}-ctr`, derived.subarray(0, length), derived.subarray(length));
  const section = Buffer.concat([aes.update(plainSection([part], 16, note)), aes.final()]);
  return { cipher: cipher, kdf: 'bcrypt', options: options, blobs: [blob], section: section };
}

/** The Poly1305 tag of a message under a one-time key of 32 bytes. */
function poly1305(key, message) {
  const number = (bytes) => BigInt(`0x${Buffer.from(bytes).reverse().toString('hex')}`);
  const prime = (1n << 130n) - 5n;
  const r = number(key.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  let accumulator = 0n;
  for (let at = 0; at < message.length; at += 16) {
    const block = message.subarray(at, at + 16);
    accumulator = ((accumulator + number(block) + (1n << BigInt(8 * block.length))) * r) % prime;
  }
  const tag = (accumulator + number(key.subarray(16))) % (1n << 128n);
  return Buffer.from(tag.toString(16).padStart(32, '0'), 'hex').reverse();
}

/** The parts of the OpenSSH file of a key pair under chacha20-poly1305@openssh.com, as ssh-keygen writes it. */
async function chacha(pair) {
  const { blob, part } = sshOf(pair);
  const { options, derived } = await derive(64);
  const stream = (counter, bytes) => {
    const iv = Buffer.concat([Buffer.of(counter), Buffer.alloc(15)]);
    return createCipheriv('chacha20', derived.subarray(0, 32), iv).update(bytes);
  };
  const section = stream(1, plainSection([part], 8));
  const tag = poly1305(stream(0, Buffer.alloc(32)), section);
  const cipher = 'chacha20-poly1305@openssh.com';
  return { cipher: cipher, kdf: 'bcrypt', options: options, blobs: [blob], section: section, tag: tag };
}

/** The plain OpenSSH file of a DSA key, its numbers read from the DER node:crypto writes. */
function dsa() {
  const { publicKey, privateKey } = generateKeyPairSync('dsa', { modulusLength: 1024, divisorLength: 160 });
  const [, algorithm, octets] = elements(elements(privateKey.export({ type: 'pkcs8', format: 'der' }))[0]);
  const [, bits] = elements(elements(publicKey.export({ type: 'spki', format: 'der' }))[0]);
  const numbers = [...elements(elements(algorithm)[1]), ...elements(bits.subarray(1))];
  const blob = Buffer.concat([string('ssh-dss'), ...numbers.map((number) => mpint(number))]);
  return openssh(plainParts([blob], [Buffer.concat([blob, mpint(elements(octets)[0])])]));
}

/** The unencrypted PuTTY v3 file of an Ed25519 key pair, with its MAC. */
function putty(pair) {
  const { blob } = sshOf(pair);
  const secret = string(Buffer.from(pair.privateKey.export({ format: 'jwk' }).d, 'base64url'));
  const signed = [string('ssh-ed25519'), string('none'), string(comment), string(blob), string(secret)];
  const mac = createHmac('sha256', Buffer.alloc(0)).update(Buffer.concat(signed)).digest('hex');
  const lines = (bytes) => {
    const text = bytes.toString('base64').match(/.{1,64}/g);
    return `${text.length}\n${text.join('\n')}\n`;
  };
  const head = `PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: ${comment}\n`;
  return `${head}Public-Lines: ${lines(blob)}Private-Lines: ${lines(secret)}Private-MAC: ${mac}\n`;
}

/** The plain OpenSSH file of an sk-ssh-ed25519@openssh.com key, its handle made up. */
function securityKey(pair) {
  const x = Buffer.from(pair.publicKey.export({ format: 'jwk' }).x, 'base64url');
  const blob = Buffer.concat([string('sk-ssh-ed25519@openssh.com'), string(x), string('ssh:')]);
  return openssh(plainParts([blob], [Buffer.concat([blob, Buffer.of(1), string(Buffer.alloc(64, 0x42)), string('')])]));
}

/** The SEC1 file of an EC key without its public point. */
function bare(privateKey) {
  const [, d, parameters] = elements(elements(privateKey.export({ type: 'sec1', format: 'der' }))[0]);
  return armour('EC PRIVATE KEY', der(0x30, der(0x02, Buffer.of(1)), der(0x04, d), der(0xa0, parameters)));
}

/** The publickey requests of user01 that a login asks the agent to sign, one per algorithm of the key. */
function requestsOf(type, blob) {
  const algorithms = type === 'ssh-rsa' ? [['ssh-rsa', 0], ['rsa-sha2-256', 2], ['rsa-sha2-512', 4]] : [[type, 0]];
  return algorithms.map(([algorithm, flags]) => {
    const head = [string(randomBytes(32)), Buffer.of(50), string('user01'), string('ssh-connection')];
    const data = Buffer.concat([...head, string('publickey'), Buffer.of(1), string(algorithm), string(blob)]);
    return { user: 'user01', algorithm: algorithm, flags: flags, data: data.toString('base64') };
  });
}

/** Generates the key pair of a kind. */
function generate(kind) {
  const [algorithm, size] = kind.split(' ');
  if (algorithm === 'ED25519') return generateKeyPairSync('ed25519');
  if (algorithm === 'ECDSA') return generateKeyPairSync('ec', { namedCurve: size });
  return generateKeyPairSync('rsa', { modulusLength: Number(size) });
}

/** The files of a key of a kind: OpenSSH plain and encrypted, then the other formats the page reads it in. */
async function family(kind) {
  const pair = generate(kind);
  const [algorithm] = kind.split(' ');
  const name = algorithm === 'ED25519' ? 'Ed25519' : kind;
  const ssh = sshOf(pair);
  const fingerprint = `SHA256:${createHash('sha256').update(ssh.blob).digest('base64').replace(/=+$/, '')}`;
  const entry = (label, format, text, cipher, note) => ({
    name: `${name} ${label}`,
    format: format,
    text: text,
    passphrase: cipher === 'none' ? '' : passphrase,
    cipher: cipher,
    kind: kind,
    comment: note,
    blob: ssh.blob.toString('base64'),
    fingerprint: fingerprint,
    publicKey: pair.publicKey,
    requests: requestsOf(ssh.type, ssh.blob),
  });
  const pem = (standard) => pair.privateKey.export({ type: standard, format: 'pem' });
  const entries = [entry('OpenSSH', 'openssh', openssh(await opensshParts(pair, 'none')), 'none', comment)];
  for (const cipher of algorithm === 'ED25519' ? ciphers.keys() : ['aes256-ctr']) {
    entries.push(entry(`OpenSSH ${cipher}`, 'openssh', openssh(await opensshParts(pair, cipher)), cipher, comment));
  }
  if (algorithm === 'ED25519') {
    const latin1 = Buffer.concat([Buffer.from(`${comment} caf`), Buffer.of(0xe9, 0xff)]);
    const text = openssh(await opensshParts(pair, 'none', latin1));
    entries.push(entry('OpenSSH Latin-1 comment', 'openssh', text, 'none', new TextDecoder().decode(latin1)));
    entries.push(entry('PKCS #8', 'pkcs8', pem('pkcs8'), 'none', ''));
  }
  if (algorithm === 'ECDSA') {
    entries.push(entry('PKCS #8', 'pkcs8', pem('pkcs8'), 'none', ''));
    entries.push(entry('SEC1', 'sec1', pem('sec1'), 'none', ''));
    entries.push(entry('SEC1 without its public key', 'sec1', bare(pair.privateKey), 'none', ''));
  }
  if (algorithm === 'RSA') {
    entries.push(entry('PKCS #1', 'pkcs1', pem('pkcs1'), 'none', ''));
    entries.push(entry('PKCS #8', 'pkcs8', pem('pkcs8'), 'none', ''));
  }
  return entries;
}

/** The texts the page refuses, each with the passphrase it is read with and its refusal code. */
async function refusalSet() {
  const [first, second] = [generateKeyPairSync('ed25519'), generateKeyPairSync('ed25519')];
  const [one, two] = [sshOf(first), sshOf(second)];
  const encrypted = await opensshParts(first, 'aes256-ctr');
  const rounds4096 = Buffer.concat([encrypted.options.subarray(0, -4), uint32(4096)]);
  const rsa = (bits) => generateKeyPairSync('rsa', { modulusLength: bits }).privateKey;
  const sealed = (key, type) => key.export({
    type: type,
    format: 'pem',
    cipher: 'aes-256-cbc',
    passphrase: passphrase,
  });
  const p224 = generateKeyPairSync('ec', { namedCurve: 'P-224' }).privateKey;
  const refusal = (name, text, code, phrase) => ({ name: name, text: text, passphrase: phrase, refusal: code });
  return [
    refusal('plain text', `${comment}\nThis note holds no key.\n`, 'not-a-key', ''),
    refusal('a certificate armour', armour('CERTIFICATE', Buffer.from(comment)), 'not-a-key', ''),
    refusal('an OpenSSH public key line', `ssh-ed25519 ${one.blob.toString('base64')} ${comment}\n`, 'public-key', ''),
    refusal('a public key armour', first.publicKey.export({ type: 'spki', format: 'pem' }), 'public-key', ''),
    refusal('a DSA OpenSSH file', dsa(), 'dsa', ''),
    refusal('a PuTTY v3 file', putty(first), 'putty', ''),
    refusal('an encrypted PEM PKCS #1 file', sealed(rsa(2048), 'pkcs1'), 'pem-encrypted', passphrase),
    refusal('a chacha20-poly1305 OpenSSH file', openssh(await chacha(first)), 'cipher', passphrase),
    refusal('an encrypted PKCS #8 armour', sealed(first.privateKey, 'pkcs8'), 'cipher', passphrase),
    refusal('an OpenSSH kdf other than bcrypt', openssh({ ...encrypted, kdf: 'argon2id', options: Buffer.alloc(0) }),
      'kdf', passphrase),
    refusal('bcrypt rounds 4096', openssh({ ...encrypted, options: rounds4096 }), 'rounds', passphrase),
    refusal('a security key', securityKey(first), 'security-key', ''),
    refusal('an OpenSSH file of two keys', openssh(plainParts([one.blob, two.blob], [one.part, two.part])),
      'several-keys', ''),
    refusal('a P-224 SEC1 key', p224.export({ type: 'sec1', format: 'pem' }), 'curve', ''),
    refusal('an RSA 768 key', rsa(768).export({ type: 'pkcs1', format: 'pem' }), 'rsa-size', ''),
    refusal('a wrong passphrase', openssh(encrypted), 'passphrase', 'passphrase-02'),
    refusal('random base64 in the OpenSSH armour', armour('OPENSSH PRIVATE KEY', randomBytes(96)), 'malformed', ''),
    refusal('a public blob that differs from the private section', openssh(plainParts([two.blob], [one.part])),
      'malformed', ''),
  ];
}

/**
 * The key files of the kinds named, of every kind when none is, each kind generated once a run: name, format, text,
 * passphrase, cipher, kind, comment, blob in base64, fingerprint, public key and the requests a login signs.
 */
export async function keys(...named) {
  const wanted = named.length > 0 ? named : kinds;
  for (const kind of wanted) {
    if (!families.has(kind)) families.set(kind, family(kind));
  }
  return (await Promise.all(wanted.map((kind) => families.get(kind)))).flat();
}

/** The texts the page refuses, generated once a run: name, text, passphrase and refusal code. */
export function refusals() {
  refused ??= refusalSet();
  return refused;
}
