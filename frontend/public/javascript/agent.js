import { UKey } from './key.js';
import { UWire } from './wire.js';

/**
 * The page's SSH agent of one key: it holds the non-extractable CryptoKeys for the tab's life and signs what the
 * signing policy allows, at most once per WebSocket the user opened.
 */
export class UAgent {
  static UKey = UKey;

  /** The signature algorithms of each kind with the agent flags they take (SSH_AGENT_RSA_SHA2_256 and _512). */
  static #algorithms = new Map([
    ['ED25519', new Map([['ssh-ed25519', 0]])],
    ['ECDSA P-256', new Map([['ecdsa-sha2-nistp256', 0]])],
    ['ECDSA P-384', new Map([['ecdsa-sha2-nistp384', 0]])],
    ['ECDSA P-521', new Map([['ecdsa-sha2-nistp521', 0]])],
    [
      'RSA',
      new Map([
        ['ssh-rsa', 0],
        ['rsa-sha2-256', 2],
        ['rsa-sha2-512', 4],
      ]),
    ],
  ]);
  static #hashes = new Map([
    ['ecdsa-sha2-nistp256', 'SHA-256'],
    ['ecdsa-sha2-nistp384', 'SHA-384'],
    ['ecdsa-sha2-nistp521', 'SHA-512'],
  ]);
  static #sessionIds = [20, 32, 48, 64];

  #keys;
  #blob;
  #kind;
  #fingerprint;
  #user = '';
  #state = 'idle';
  #count = 0;

  /**
   * Keeps the imported key for the tab's life.
   * @param {Map<string, CryptoKey>} keys The CryptoKeys by signature algorithm, as `UKey.unlock` gives them.
   * @param {Uint8Array} blob The SSH wire blob of the public key.
   * @param {string} kind The kind: `ED25519`, `ECDSA P-256`, `ECDSA P-384`, `ECDSA P-521` or `RSA <bits>`.
   * @param {string} fingerprint The fingerprint as ssh-keygen prints it.
   */
  load(keys, blob, kind, fingerprint) {
    this.#keys = keys;
    this.#blob = blob;
    this.#kind = kind;
    this.#fingerprint = fingerprint;
  }

  /** Drops the key. */
  forget() {
    this.#keys = undefined;
    this.#blob = undefined;
    this.#kind = undefined;
    this.#fingerprint = undefined;
  }

  /**
   * Returns the identity the connect message announces.
   * @returns {string|undefined} The base64 of the public key's blob, or undefined without a key.
   */
  identity() {
    return this.#blob && UWire.encode64(this.#blob);
  }

  /**
   * Returns the kind of the loaded key.
   * @returns {string|undefined} The kind, or undefined without a key.
   */
  kind() {
    return this.#kind;
  }

  /**
   * Returns the fingerprint of the loaded key.
   * @returns {string|undefined} The fingerprint, or undefined without a key.
   */
  fingerprint() {
    return this.#fingerprint;
  }

  /**
   * Opens the signing window of a WebSocket the user opened with Connect or Reconnect: one signature allowed.
   * @param {string} user The user name the connect message sends.
   */
  begin(user) {
    this.#user = user;
    this.#state = 'authenticating';
    this.#count = 0;
  }

  /** Closes the signing window: the shell is ready. */
  ready() {
    this.#state = 'active';
  }

  /**
   * Answers a sign request of the bridge; the signature is counted before WebCrypto signs, so a second request
   * that arrives meanwhile is refused.
   * @param {Uint8Array} data The bytes to sign.
   * @param {number} flags The agent flags: 0, 2 (rsa-sha2-256) or 4 (rsa-sha2-512).
   * @returns {Promise<Uint8Array|null>} The SSH wire signature, or null for a refusal.
   */
  async sign(data, flags) {
    const request = {
      data: data,
      flags: flags,
      user: this.#user,
      blob: this.#blob,
      kind: this.#kind,
      state: this.#state,
      count: this.#count,
    };
    if (UAgent.judge(request) !== null) return null;
    this.#count++;
    const algorithm = UAgent.#request(data).algorithm;
    const key = this.#keys.get(algorithm);
    const hash = UAgent.#hashes.get(algorithm);
    const parameters = hash === undefined ? key.algorithm.name : { name: 'ECDSA', hash: hash };
    const signature = new Uint8Array(await globalThis.crypto.subtle.sign(parameters, key, data));
    return UWire.concat(UWire.string(algorithm), UWire.string(UAgent.#body(algorithm, signature)));
  }

  /**
   * Judges a sign request against the signing policy.
   * @param {Object} request The request and the agent's state.
   * @param {Uint8Array} request.data The bytes to sign.
   * @param {number} request.flags The agent flags.
   * @param {string} request.user The user name of the connect message.
   * @param {Uint8Array|undefined} request.blob The loaded key's blob.
   * @param {string|undefined} request.kind The loaded key's kind.
   * @param {string} request.state `idle`, `authenticating` or `active`.
   * @param {number} request.count The signatures already given on this WebSocket.
   * @returns {string|null} Null to sign, else the reason: `state`, `count`, `data`, `user`, `key` or `flags`.
   */
  static judge({ data, flags, user, blob, kind, state, count }) {
    if (state !== 'authenticating') return 'state';
    if (count !== 0) return 'count';
    const request = UAgent.#request(data);
    if (request === null) return 'data';
    if (request.user !== user) return 'user';
    if (blob === undefined || !UAgent.#equal(request.blob, blob)) return 'key';
    const algorithms = UAgent.#algorithms.get(kind.replace(/^RSA .*/, 'RSA'));
    return algorithms.get(request.algorithm) === flags ? null : 'flags';
  }

  /** Reads an SSH publickey userauth request with its signature flag set, or null for anything else. */
  static #request(data) {
    const wire = new UWire(data);
    try {
      if (!UAgent.#sessionIds.includes(wire.string().length) || wire.byte() !== 50) return null;
      const user = wire.text();
      if (wire.text() !== 'ssh-connection' || wire.text() !== 'publickey' || wire.byte() !== 1) return null;
      const request = { user: user, algorithm: wire.text(), blob: wire.string() };
      wire.end();
      return request;
    } catch {
      return null;
    }
  }

  /** Writes WebCrypto's signature as SSH carries it: ECDSA's r||s as two mpints, the others as they are. */
  static #body(algorithm, signature) {
    if (!UAgent.#hashes.has(algorithm)) return signature;
    const half = signature.length / 2;
    return UWire.concat(UWire.mpint(signature.subarray(0, half)), UWire.mpint(signature.subarray(half)));
  }

  static #equal(a, b) {
    return a.length === b.length && a.every((byte, index) => byte === b[index]);
  }
}
