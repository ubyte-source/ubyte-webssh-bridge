import { UWire } from './wire.js';
import { UDer } from './der.js';
import { UBcrypt } from './bcrypt.js';

/**
 * A refusal of a key: its code, the text the page shows and, when one exists, the command that converts the key.
 */
class Refusal {
  static #texts = {
    'too-large': ['This file is over 16384 bytes, larger than any private key.'],
    'not-a-key': ['This is not a private key.'],
    'public-key': ['This is a public key; drop the private one.'],
    dsa: ['DSA keys are not supported; make a new key.', 'ssh-keygen -t ed25519'],
    putty: [
      'PuTTY keys are read once converted to OpenSSH.',
      'puttygen <file> -O private-openssh-new -o <file>.openssh',
    ],
    'pem-encrypted': ['This key is encrypted in the old PEM format.', 'ssh-keygen -p -f <file>'],
    cipher: ['This key is encrypted with a cipher the page does not read.', 'ssh-keygen -p -f <file>'],
    kdf: ['This key is protected by a key derivation the page does not read.', 'ssh-keygen -p -f <file>'],
    rounds: ['This key asks more than 2048 bcrypt rounds.', 'ssh-keygen -p -f <file>'],
    'security-key': ['A hardware security key cannot sign in a browser.'],
    'several-keys': ['This file holds several keys; drop a file with one.'],
    curve: ['This curve is not supported; use Ed25519, P-256, P-384 or P-521.'],
    'rsa-size': ['RSA keys sign here with 1024 to 16384 bits.'],
    passphrase: ['Wrong passphrase.'],
    malformed: ['This key does not read.'],
  };

  /** @type {string} The code. */
  code;
  /** @type {string} The text the page shows. */
  text;
  /** @type {string|null} The command that converts the key, or null. */
  command;

  /**
   * Constructs a new Refusal instance.
   * @param {string} code The code: too-large, not-a-key, public-key, dsa, putty, pem-encrypted, cipher, kdf, rounds,
   *   security-key, several-keys, curve, rsa-size, passphrase, unsupported or malformed.
   * @param {string} [kind] The kind of the key, which the text of `unsupported` names.
   */
  constructor(code, kind) {
    const [text, command] = code === 'unsupported' ? [Refusal.#unsupported(kind)] : Refusal.#texts[code];
    this.code = code;
    this.text = text;
    this.command = command ?? null;
  }

  /**
   * Puts the key's file name, quoted for a POSIX shell, in place of `<file>` in the command; a pasted key keeps
   * `<file>`.
   * @param {string} name The file name, or `pasted key`.
   * @returns {Refusal} This refusal.
   */
  name(name) {
    if (this.command !== null && name !== 'pasted key') {
      // A function replacement keeps a `$` of the name literal.
      this.command = this.command.replaceAll('<file>', () => Refusal.#quote(name));
    }
    return this;
  }

  static #unsupported(kind) {
    const name = kind === 'ED25519' ? 'Ed25519' : kind.replace(/^RSA .*/, 'RSA');
    return `This browser cannot sign with ${name} keys.`;
  }

  /** Quotes a name for a POSIX shell; `./` keeps a leading `-` from reading as an option. */
  static #quote(name) {
    const path = name.startsWith('-') ? `./${name}` : name;
    return /^[\w./-]+$/.test(path) ? path : `'${path.replaceAll("'", "'\\''")}'`;
  }
}

/**
 * A private key the user dropped, chose or pasted: what it is, read at once, and its import into WebCrypto.
 * `inspect` overwrites the bytes it receives; the key holds its decoded body until `unlock` imports it, `discard`
 * drops it, or a refusal other than `passphrase` ends it.
 */
export class UKey {
  static UWire = UWire;
  static UDer = UDer;
  static UBcrypt = UBcrypt;
  static Refusal = Refusal;

  static #maxBytes = 16384;
  static #maxRounds = 2048;
  static #minModulusBits = 1024;
  static #maxModulusBits = 16384;

  static #ciphers = new Map([
    ['aes128-ctr', 16],
    ['aes192-ctr', 24],
    ['aes256-ctr', 32],
  ]);
  /** The curves the page reads; the prime p, the order n and the generator gx, gy in base64, big-endian. */
  static #curves = [
    {
      name: 'nistp256',
      oid: '1.2.840.10045.3.1.7',
      crv: 'P-256',
      size: 32,
      p: '/////wAAAAEAAAAAAAAAAAAAAAD///////////////8=',
      n: '/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVE=',
      gx: 'axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY=',
      gy: 'T+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU=',
    },
    {
      name: 'nistp384',
      oid: '1.3.132.0.34',
      crv: 'P-384',
      size: 48,
      p: '//////////////////////////////////////////7/////AAAAAAAAAAD/////',
      n: '////////////////////////////////x2NNgfQ3Ld9YGg2ySLCneuzsGWrMxSlz',
      gx: 'qofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3',
      gy: 'NhfeSpYmLG9dnpi/kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f',
    },
    {
      name: 'nistp521',
      oid: '1.3.132.0.35',
      crv: 'P-521',
      size: 66,
      p: 'Af//////////////////////////////////////////////////////////////////////////////////////',
      n: 'Af//////////////////////////////////////////+lGGh4O/L5Zrf8wBSPcJpdA7tcm4iZxHrrtvtx6ROGQJ',
      gx: 'AMaFjga3BATpzZ4+y2YjlbRCnGSBOQU/tSH4KK9ga009uqFLXnfv51ko/h3BJ6L/qN4zSLPBhWpCm/l+fjHC5b1m',
      gy: 'ARg5KWp4mjvABFyKX7QsfRvZmPVESVebRGgXr70XJz5mLJfucple9CZAxVC5AT+tB2E1PHCGonLCQIi+lHaf0WZQ',
    },
  ];
  static #signable = new WeakMap();

  /** @type {string} The file name, or `pasted key`. */
  name;
  /** @type {string} `openssh`, `pkcs8`, `pkcs1` or `sec1`. */
  format;
  /** @type {string} `ED25519`, `ECDSA P-256`, `ECDSA P-384`, `ECDSA P-521` or `RSA <bits>`. */
  kind;
  /** @type {string} The comment, or empty when the file has none or it is encrypted. */
  comment;
  /** @type {boolean} True when a passphrase is needed. */
  encrypted;
  /** @type {Uint8Array|undefined} The public blob, when known before the import. */
  blob;
  /** @type {string|undefined} The fingerprint, when known before the import. */
  fingerprint;

  #body;
  #parts;
  #encryption;

  /**
   * Constructs a new UKey instance; `inspect` builds it.
   * @param {string} name The file name, or `pasted key`.
   * @param {Object} read What the file holds.
   */
  constructor(name, read) {
    this.name = name;
    this.format = read.format;
    this.kind = UKey.#kind(read.parts ?? read.encryption.header);
    this.comment = read.comment;
    this.encrypted = read.encryption !== undefined;
    this.#body = read.body;
    this.#parts = read.parts;
    this.#encryption = read.encryption;
  }

  /**
   * Reads a key file at once; the bytes are overwritten with zeros whatever the outcome.
   * @param {Uint8Array} bytes The file's bytes.
   * @param {string} name The file name, or `pasted key`.
   * @returns {Promise<UKey>} The key; a `UKey.Refusal` rejects it.
   */
  static async inspect(bytes, name) {
    let key;
    try {
      key = new UKey(name, UKey.#consume(bytes));
      if (!globalThis.crypto?.subtle) throw new Refusal('unsupported', key.kind);
      key.blob = UKey.#blob(key.#encryption?.header ?? key.#parts);
      key.fingerprint = key.blob && (await UKey.#fingerprint(key.blob));
      return key;
    } catch (error) {
      key?.discard();
      throw error instanceof Refusal ? error.name(name) : new Refusal('malformed');
    }
  }

  /**
   * Tells whether a text holds a private key armour or a PuTTY key.
   * @param {string} text The text.
   * @returns {boolean} True when it does.
   */
  static armoured(text) {
    return /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|PuTTY-User-Key-File-/.test(text);
  }

  /**
   * Tells whether this browser signs with a kind of key; the answer is kept per kind.
   * @param {string} kind The kind.
   * @param {SubtleCrypto|null} [subtle] The WebCrypto to probe; without one nothing signs.
   * @returns {Promise<boolean>} True when it signs with it.
   */
  static signable(kind, subtle = globalThis.crypto?.subtle) {
    if (!subtle) return Promise.resolve(false);
    if (!UKey.#signable.has(subtle)) UKey.#signable.set(subtle, new Map());
    const kinds = UKey.#signable.get(subtle);
    if (!kinds.has(kind)) kinds.set(kind, UKey.#probe(kind, subtle));
    return kinds.get(kind);
  }

  /**
   * Decrypts the key when it is encrypted and imports it into WebCrypto, non-extractable, for signing; the
   * passphrase bytes are overwritten with zeros. After a `passphrase` refusal the key can be unlocked again.
   * @param {Uint8Array} passphrase The passphrase's UTF-8 bytes (empty for a plain key).
   * @param {function(number, number): void} progress Called with the bcrypt round done and the rounds.
   * @returns {Promise<{keys: Map<string, CryptoKey>, blob: Uint8Array, kind: string, fingerprint: string}>} What
   *   `UAgent.load` takes, the CryptoKeys by signature algorithm; a `UKey.Refusal` rejects it.
   */
  async unlock(passphrase, progress) {
    try {
      const loaded = await this.#unlock(passphrase, progress);
      this.discard();
      return loaded;
    } catch (error) {
      if (!(error instanceof Refusal) || error.code !== 'passphrase') this.discard();
      throw error instanceof Refusal ? error : new Refusal('malformed');
    }
  }

  /** Overwrites the key's material with zeros and drops it. */
  discard() {
    this.#body?.fill(0);
    this.#body = undefined;
    this.#parts = undefined;
    this.#encryption = undefined;
  }

  /** Decrypts the section of an encrypted key and imports the parts; the passphrase and section end as zeros. */
  async #unlock(passphrase, progress) {
    let section;
    try {
      if (this.#encryption !== undefined) section = await this.#decrypt(passphrase, progress);
      const parts = section === undefined ? this.#parts : UKey.#private(section, this.#encryption.header, true).parts;
      return await UKey.#load(parts);
    } finally {
      passphrase.fill(0);
      section?.fill(0);
    }
  }

  async #decrypt(passphrase, progress) {
    if (passphrase.length === 0) throw new Refusal('passphrase');
    const { cipher, salt, rounds, section } = this.#encryption;
    const length = UKey.#ciphers.get(cipher);
    const derived = await UBcrypt.pbkdf(passphrase, salt, rounds, length + 16, progress);
    try {
      const subtle = globalThis.crypto.subtle;
      const aes = await subtle.importKey('raw', derived.subarray(0, length), 'AES-CTR', false, ['decrypt']);
      const counter = derived.subarray(length);
      return new Uint8Array(await subtle.decrypt({ name: 'AES-CTR', counter: counter, length: 128 }, aes, section));
    } finally {
      derived.fill(0);
    }
  }

  /** Reads a file of at most 16384 bytes, then overwrites its bytes with zeros whatever the outcome. */
  static #consume(bytes) {
    try {
      if (bytes.length > UKey.#maxBytes) throw new Refusal('too-large');
      return UKey.#read(bytes);
    } finally {
      bytes.fill(0);
    }
  }

  /** Reads the armour, or names what the text is instead. */
  static #read(bytes) {
    const begin = UKey.#find(bytes, '-----BEGIN ', 0);
    if (begin < 0) throw new Refusal(UKey.#unarmoured(bytes));
    const start = begin + '-----BEGIN '.length;
    const close = UKey.#find(bytes, '-----', start);
    const label = close < 0 ? '' : String.fromCharCode(...bytes.subarray(start, Math.min(close, start + 65)));
    if (!/^[A-Z0-9 ]{1,64}$/.test(label)) throw new Refusal('not-a-key');
    const format = UKey.#format(label);
    const end = UKey.#find(bytes, `-----END ${label}-----`, close + 5);
    if (end < 0) throw new Refusal('malformed');
    const region = bytes.subarray(close + 5, end);
    if (UKey.#find(region, 'Proc-Type: 4,ENCRYPTED', 0) >= 0) throw new Refusal('pem-encrypted');
    const body = UWire.decode64(region);
    try {
      return { format: format, body: body, ...UKey.#formats[format](body) };
    } catch (error) {
      body.fill(0);
      throw error;
    }
  }

  static #unarmoured(bytes) {
    let start = 0;
    while (start < bytes.length && /\s/.test(String.fromCharCode(bytes[start]))) start++;
    if (UKey.#find(bytes, 'PuTTY-User-Key-File-', start) === start) return 'putty';
    const head = String.fromCharCode(...bytes.subarray(start, start + 64));
    return /^(ssh|ecdsa|sk)-[\w@.-]+\s+AAAA/.test(head) ? 'public-key' : 'not-a-key';
  }

  static #format(label) {
    switch (label) {
      case 'OPENSSH PRIVATE KEY':
        return 'openssh';
      case 'PRIVATE KEY':
        return 'pkcs8';
      case 'RSA PRIVATE KEY':
        return 'pkcs1';
      case 'EC PRIVATE KEY':
        return 'sec1';
      case 'DSA PRIVATE KEY':
        throw new Refusal('dsa');
      case 'ENCRYPTED PRIVATE KEY':
        throw new Refusal('cipher');
      default:
        throw new Refusal(label.endsWith('PUBLIC KEY') ? 'public-key' : 'not-a-key');
    }
  }

  static #formats = {
    openssh: (body) => UKey.#openssh(body),
    pkcs8: (body) => UKey.#pkcs8(body),
    pkcs1: (body) => ({ parts: UKey.#pkcs1(body), comment: '' }),
    sec1: (body) => ({ parts: UKey.#sec1(body), comment: '' }),
  };

  /** Reads `openssh-key-v1`: one key, its public blob in clear, the private section plain or under bcrypt. */
  static #openssh(body) {
    const wire = new UWire(body);
    if (!UKey.#equal(wire.bytes(15), new TextEncoder().encode('openssh-key-v1\0'))) throw new Refusal('malformed');
    const cipher = wire.text();
    const kdf = wire.text();
    const options = wire.string();
    if (wire.uint32() !== 1) throw new Refusal('several-keys');
    const header = UKey.#public(wire.string());
    const plain = cipher === 'none' && kdf === 'none';
    if (!plain && !UKey.#ciphers.has(cipher)) throw new Refusal(cipher === 'none' ? 'malformed' : 'cipher');
    if (!plain && kdf !== 'bcrypt') throw new Refusal(kdf === 'none' ? 'malformed' : 'kdf');
    const section = wire.string();
    wire.end();
    if (plain) return UKey.#private(section, header, false);
    const settings = new UWire(options);
    const salt = settings.string();
    const rounds = settings.uint32();
    settings.end();
    if (rounds > UKey.#maxRounds) throw new Refusal('rounds');
    if (rounds === 0 || salt.length === 0) throw new Refusal('malformed');
    return {
      comment: '',
      encryption: { cipher: cipher, salt: salt, rounds: rounds, section: section, header: header },
    };
  }

  /** Reads an OpenSSH public blob into the parts the page needs. */
  static #public(blob) {
    const wire = new UWire(blob);
    const type = wire.text();
    const parts = UKey.#openParts(type, wire, false);
    wire.end();
    return parts;
  }

  /** Reads the plain private section: check integers, the key, its comment, the padding. */
  static #private(section, header, encrypted) {
    const wire = new UWire(section);
    if (wire.uint32() !== wire.uint32()) throw new Refusal(encrypted ? 'passphrase' : 'malformed');
    const parts = UKey.#openParts(wire.text(), wire, true);
    const comment = new TextDecoder().decode(wire.string());
    for (let pad = 1; wire.remaining() > 0; pad++) if (wire.byte() !== pad) throw new Refusal('malformed');
    if (!UKey.#equal(UKey.#blob(parts), UKey.#blob(header))) throw new Refusal('malformed');
    return { parts: parts, comment: comment };
  }

  /** Reads the parts of one key in the OpenSSH order, public or private. */
  static #openParts(type, wire, secret) {
    if (type === 'ssh-ed25519') {
      const x = wire.string();
      if (!secret) return UKey.#ed25519({ x: x });
      const pair = wire.string();
      if (pair.length !== 64 || !UKey.#equal(pair.subarray(32), x)) throw new Refusal('malformed');
      return UKey.#ed25519({ x: x, seed: pair.subarray(0, 32) });
    }
    if (type === 'ssh-rsa') {
      if (!secret) return UKey.#rsa({ e: wire.mpint(), n: wire.mpint() });
      const [n, e, d, qi, p, q] = Array.from({ length: 6 }, () => wire.mpint());
      return UKey.#rsa({ n: n, e: e, d: d, p: p, q: q, qi: qi });
    }
    if (type === 'ssh-dss') throw new Refusal('dsa');
    if (type.startsWith('sk-')) throw new Refusal('security-key');
    if (!type.startsWith('ecdsa-sha2-')) throw new Refusal('malformed');
    const curve = UKey.#curves.find((entry) => `ecdsa-sha2-${entry.name}` === type);
    if (curve === undefined) throw new Refusal('curve');
    if (wire.text() !== curve.name) throw new Refusal('malformed');
    const point = wire.string();
    return UKey.#ecdsa({ curve: curve, point: point, d: secret ? wire.mpint() : undefined });
  }

  /** Reads PKCS #8: RSA, EC or Ed25519, the public key optional. */
  static #pkcs8(body) {
    const outer = new UDer(body);
    const info = outer.sequence();
    outer.end();
    const version = info.integer();
    if (version.length > 1 || version[0] > 1) throw new Refusal('malformed');
    const algorithm = info.sequence();
    const identifier = algorithm.oid();
    const key = info.octets();
    if (info.next(UDer.EXPLICIT_0)) info.element(UDer.EXPLICIT_0);
    const x = info.next(UDer.IMPLICIT_1) ? info.bits(UDer.IMPLICIT_1) : undefined;
    info.end();
    switch (identifier) {
      case '1.2.840.113549.1.1.1':
        return { parts: UKey.#pkcs1(key), comment: '' };
      case '1.2.840.10045.2.1':
        return { parts: UKey.#sec1(key, UKey.#curve(algorithm.oid())), comment: '' };
      case '1.3.101.112': {
        const seed = new UDer(key);
        const parts = UKey.#ed25519({ seed: seed.octets(), x: x });
        seed.end();
        return { parts: parts, comment: '' };
      }
      case '1.2.840.10040.4.1':
        throw new Refusal('dsa');
      default:
        throw new Refusal('malformed');
    }
  }

  /** Reads PKCS #1 RSAPrivateKey, two primes. */
  static #pkcs1(body) {
    const outer = new UDer(body);
    const key = outer.sequence();
    outer.end();
    if (key.integer().length !== 0) throw new Refusal('malformed');
    const [n, e, d, p, q, dp, dq, qi] = Array.from({ length: 8 }, () => key.integer());
    key.end();
    return UKey.#rsa({ n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi });
  }

  /** Reads SEC1 ECPrivateKey; its curve is the PKCS #8 algorithm's or its own parameter. */
  static #sec1(body, curve) {
    const outer = new UDer(body);
    const key = outer.sequence();
    outer.end();
    const version = key.integer();
    if (version.length !== 1 || version[0] !== 1) throw new Refusal('malformed');
    const d = key.octets();
    const named = key.next(UDer.EXPLICIT_0) ? UKey.#curve(new UDer(key.element(UDer.EXPLICIT_0)).oid()) : curve;
    if (named === undefined || (curve !== undefined && named !== curve)) throw new Refusal('malformed');
    const point = key.next(UDer.EXPLICIT_1) ? new UDer(key.element(UDer.EXPLICIT_1)).bits() : undefined;
    key.end();
    return UKey.#ecdsa({ curve: named, point: point, d: d });
  }

  static #curve(identifier) {
    const curve = UKey.#curves.find((entry) => entry.oid === identifier);
    if (curve === undefined) throw new Refusal('curve');
    return curve;
  }

  static #ed25519(parts) {
    if ((parts.x !== undefined && parts.x.length !== 32) || (parts.seed !== undefined && parts.seed.length !== 32)) {
      throw new Refusal('malformed');
    }
    return { type: 'ed25519', ...parts };
  }

  static #ecdsa(parts) {
    const size = parts.curve.size;
    if (parts.point !== undefined && (parts.point.length !== 2 * size + 1 || parts.point[0] !== 4)) {
      throw new Refusal('malformed');
    }
    if (parts.d !== undefined && UKey.#trim(parts.d).length > size) throw new Refusal('malformed');
    return { type: 'ecdsa', ...parts };
  }

  static #rsa(parts) {
    const bits = UKey.#bits(parts.n);
    if (bits < UKey.#minModulusBits || bits > UKey.#maxModulusBits) throw new Refusal('rsa-size');
    return { type: 'rsa', ...parts };
  }

  static #kind(parts) {
    if (parts.type === 'ed25519') return 'ED25519';
    if (parts.type === 'ecdsa') return `ECDSA ${parts.curve.crv}`;
    return `RSA ${UKey.#bits(parts.n)}`;
  }

  /** Builds the public blob, or undefined while the public part is unknown. */
  static #blob(parts) {
    if (parts.type === 'ed25519') return parts.x && UWire.concat(UWire.string('ssh-ed25519'), UWire.string(parts.x));
    if (parts.type === 'rsa') return UWire.concat(UWire.string('ssh-rsa'), UWire.mpint(parts.e), UWire.mpint(parts.n));
    const name = parts.curve.name;
    const point = parts.point && UWire.string(parts.point);
    return point && UWire.concat(UWire.string(`ecdsa-sha2-${name}`), UWire.string(name), point);
  }

  static async #fingerprint(blob) {
    const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', blob));
    return `SHA256:${UWire.encodeRaw64(digest)}`;
  }

  /** Imports the parts into WebCrypto and gives what the agent loads. */
  static async #load(parts) {
    const complete = await UKey.#complete(parts);
    const keys = await UKey.#importers[complete.type](complete);
    const blob = UKey.#blob(complete);
    return { keys: keys, blob: blob, kind: UKey.#kind(complete), fingerprint: await UKey.#fingerprint(blob) };
  }

  static #importers = {
    ed25519: async (parts) => {
      const jwk = { kty: 'OKP', crv: 'Ed25519', d: UWire.encodeUrl64(parts.seed), x: UWire.encodeUrl64(parts.x) };
      return new Map([['ssh-ed25519', await UKey.#import(jwk, { name: 'Ed25519' })]]);
    },
    ecdsa: async (parts) => {
      const size = parts.curve.size;
      const d = UKey.#pad(parts.d, size);
      const jwk = {
        kty: 'EC',
        crv: parts.curve.crv,
        d: UWire.encodeUrl64(d),
        x: UWire.encodeUrl64(parts.point.subarray(1, 1 + size)),
        y: UWire.encodeUrl64(parts.point.subarray(1 + size)),
      };
      d.fill(0);
      const algorithm = { name: 'ECDSA', namedCurve: parts.curve.crv };
      return new Map([[`ecdsa-sha2-${parts.curve.name}`, await UKey.#import(jwk, algorithm)]]);
    },
    rsa: async (parts) => {
      const dp = parts.dp ?? UKey.#remainder(parts.d, parts.p);
      const dq = parts.dq ?? UKey.#remainder(parts.d, parts.q);
      const jwk = { kty: 'RSA' };
      for (const [name, value] of Object.entries({ ...parts, dp: dp, dq: dq })) {
        if (value instanceof Uint8Array) jwk[name] = UWire.encodeUrl64(UKey.#trim(value));
      }
      if (parts.dp === undefined) dp.fill(0);
      if (parts.dq === undefined) dq.fill(0);
      const hashes = [
        ['ssh-rsa', 'SHA-1'],
        ['rsa-sha2-256', 'SHA-256'],
        ['rsa-sha2-512', 'SHA-512'],
      ];
      const keys = new Map();
      for (const [algorithm, hash] of hashes) {
        keys.set(algorithm, await UKey.#import(jwk, { name: 'RSASSA-PKCS1-v1_5', hash: hash }));
      }
      return keys;
    },
  };

  static #import(jwk, algorithm) {
    return globalThis.crypto.subtle.importKey('jwk', jwk, algorithm, false, ['sign']);
  }

  /**
   * Gives the parts with their public key: an EC key read without its point gets d·G, and an Ed25519 key read
   * without x is imported once extractable from PKCS #8, its JWK read for x, and dropped.
   */
  static async #complete(parts) {
    if (parts.type === 'rsa' || (parts.x ?? parts.point) !== undefined) return parts;
    if (parts.type === 'ecdsa') return { ...parts, point: UKey.#point(parts.curve, parts.d) };
    const subtle = globalThis.crypto.subtle;
    const inner = UDer.write(UDer.OCTET_STRING, parts.seed);
    const der = UDer.pkcs8(['1.3.101.112'], inner);
    try {
      const key = await subtle.importKey('pkcs8', der, { name: 'Ed25519' }, true, ['sign']);
      return { ...parts, x: UWire.decodeUrl64((await subtle.exportKey('jwk', key)).x) };
    } finally {
      inner.fill(0);
      der.fill(0);
    }
  }

  /**
   * Computes the public point d·G of an EC private number as 04||X||Y, in Jacobian coordinates; a number outside
   * 1 to n - 1 is refused.
   */
  static #point(curve, d) {
    const [p, n, gx, gy] = [curve.p, curve.n, curve.gx, curve.gy].map((text) => UKey.#big(UWire.decode64(text)));
    const scalar = UKey.#big(d);
    if (scalar === 0n || scalar >= n) throw new Refusal('malformed');
    let point = [gx, gy, 1n];
    for (const bit of scalar.toString(2).slice(1)) {
      point = UKey.#double(point, p);
      if (bit === '1') point = UKey.#add(point, gx, gy, p);
    }
    const [x, y, z] = point;
    const inverse = UKey.#power(z, p - 2n, p);
    const square = (inverse * inverse) % p;
    const coordinates = [(x * square) % p, (((y * square) % p) * inverse) % p];
    return UWire.concat(Uint8Array.of(4), ...coordinates.map((value) => UKey.#bytes(value, curve.size)));
  }

  /** Doubles a point in Jacobian coordinates on a curve whose a is -3. */
  static #double([x, y, z], p) {
    const delta = (z * z) % p;
    const gamma = (y * y) % p;
    const beta = (x * gamma) % p;
    const alpha = (3n * (x - delta) * (x + delta)) % p;
    const x3 = UKey.#modulo(alpha * alpha - 8n * beta, p);
    const y3 = UKey.#modulo(alpha * (4n * beta - x3) - 8n * gamma * gamma, p);
    return [x3, y3, UKey.#modulo((y + z) ** 2n - gamma - delta, p)];
  }

  /** Adds the affine point (gx, gy) to a point in Jacobian coordinates that is neither it, its opposite nor zero. */
  static #add([x, y, z], gx, gy, p) {
    const zz = (z * z) % p;
    const h = (gx * zz - x) % p;
    const r = (2n * (((gy * z) % p) * zz - y)) % p;
    const hh = (h * h) % p;
    const i = (4n * hh) % p;
    const j = (h * i) % p;
    const v = (x * i) % p;
    const x3 = UKey.#modulo(r * r - j - 2n * v, p);
    const y3 = UKey.#modulo(r * (v - x3) - 2n * y * j, p);
    return [x3, y3, UKey.#modulo((z + h) ** 2n - zz - hh, p)];
  }

  static #power(base, exponent, modulus) {
    let result = 1n;
    for (let square = base, rest = exponent; rest > 0n; rest >>= 1n, square = (square * square) % modulus) {
      if (rest & 1n) result = (result * square) % modulus;
    }
    return result;
  }

  static #modulo(value, modulus) {
    return ((value % modulus) + modulus) % modulus;
  }

  static async #probe(kind, subtle) {
    if (kind.startsWith('RSA ')) return true;
    const algorithm = kind === 'ED25519' ? { name: 'Ed25519' } : { name: 'ECDSA', namedCurve: kind.slice(6) };
    try {
      await subtle.generateKey(algorithm, false, ['sign']);
      return true;
    } catch {
      return false;
    }
  }

  /** Computes `d mod (prime - 1)`, which PKCS #1 holds and OpenSSH leaves out. */
  static #remainder(d, prime) {
    return UKey.#bytes(UKey.#big(d) % (UKey.#big(prime) - 1n), prime.length);
  }

  /** Writes a non-negative number big-endian in a given number of bytes. */
  static #bytes(value, length) {
    const bytes = new Uint8Array(length);
    for (let at = length - 1, rest = value; rest > 0n; at--, rest >>= 8n) bytes[at] = Number(rest & 0xffn);
    return bytes;
  }

  static #big(bytes) {
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    return value;
  }

  static #bits(magnitude) {
    const value = UKey.#trim(magnitude);
    return value.length === 0 ? 0 : 8 * value.length - Math.clz32(value[0]) + 24;
  }

  static #trim(magnitude) {
    let start = 0;
    while (start < magnitude.length && magnitude[start] === 0) start++;
    return magnitude.subarray(start);
  }

  static #pad(magnitude, size) {
    const value = UKey.#trim(magnitude);
    const padded = new Uint8Array(size);
    padded.set(value, size - value.length);
    return padded;
  }

  static #equal(a, b) {
    return a.length === b.length && a.every((byte, index) => byte === b[index]);
  }

  static #find(bytes, needle, from) {
    const target = new TextEncoder().encode(needle);
    for (let at = from; at <= bytes.length - target.length; at++) {
      let index = 0;
      while (index < target.length && bytes[at + index] === target[index]) index++;
      if (index === target.length) return at;
    }
    return -1;
  }
}
