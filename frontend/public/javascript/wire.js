/**
 * The SSH wire format (RFC 4251): an instance reads a byte array in order, the static methods write the parts of
 * a message and the base64 forms the page and the bridge exchange. Every value an instance reads is a view of its
 * array, so overwriting the array overwrites them.
 */
export class UWire {
  static #standard = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  static #url = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  static #values = new Map();

  #bytes;
  #at = 0;

  /**
   * Constructs a new UWire reader.
   * @param {Uint8Array} bytes The bytes to read.
   */
  constructor(bytes) {
    this.#bytes = bytes;
  }

  /**
   * Reads raw bytes.
   * @param {number} length How many.
   * @returns {Uint8Array} A view of them.
   */
  bytes(length) {
    if (length > this.#bytes.length - this.#at) throw new RangeError('wire: short input');
    const view = this.#bytes.subarray(this.#at, this.#at + length);
    this.#at += length;
    return view;
  }

  /**
   * Reads one byte.
   * @returns {number} The byte.
   */
  byte() {
    return this.bytes(1)[0];
  }

  /**
   * Reads a boolean, which is one byte.
   * @returns {boolean} False for 0, true otherwise.
   */
  bool() {
    return this.byte() !== 0;
  }

  /**
   * Reads a big-endian uint32.
   * @returns {number} The number.
   */
  uint32() {
    const [a, b, c, d] = this.bytes(4);
    return ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
  }

  /**
   * Reads a string: a uint32 length and that many bytes.
   * @returns {Uint8Array} A view of the bytes.
   */
  string() {
    return this.bytes(this.uint32());
  }

  /**
   * Reads a string of UTF-8 text.
   * @returns {string} The text.
   */
  text() {
    return new TextDecoder('utf-8', { fatal: true }).decode(this.string());
  }

  /**
   * Reads a non-negative mpint.
   * @returns {Uint8Array} A view of its magnitude, big-endian, without leading zeros.
   */
  mpint() {
    const value = this.string();
    if (value.length > 0 && value[0] >= 0x80) throw new RangeError('wire: negative mpint');
    let start = 0;
    while (start < value.length && value[start] === 0) start++;
    return value.subarray(start);
  }

  /**
   * Tells how many bytes remain.
   * @returns {number} The count.
   */
  remaining() {
    return this.#bytes.length - this.#at;
  }

  /** Refuses bytes left after the last part. */
  end() {
    if (this.remaining() !== 0) throw new RangeError('wire: trailing bytes');
  }

  /**
   * Writes a big-endian uint32.
   * @param {number} value The number.
   * @returns {Uint8Array} Its four bytes.
   */
  static uint32(value) {
    return Uint8Array.of(value >>> 24, value >>> 16, value >>> 8, value);
  }

  /**
   * Writes a string.
   * @param {Uint8Array|string} value The bytes, or a text written as UTF-8.
   * @returns {Uint8Array} The length and the bytes.
   */
  static string(value) {
    const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
    return UWire.concat(UWire.uint32(bytes.length), bytes);
  }

  /**
   * Writes a non-negative mpint.
   * @param {Uint8Array} magnitude The number, big-endian, with or without leading zeros.
   * @returns {Uint8Array} The string of its two's complement form.
   */
  static mpint(magnitude) {
    let start = 0;
    while (start < magnitude.length && magnitude[start] === 0) start++;
    const value = magnitude.subarray(start);
    if (value.length > 0 && value[0] >= 0x80) return UWire.string(UWire.concat(Uint8Array.of(0), value));
    return UWire.string(value);
  }

  /**
   * Joins byte arrays.
   * @param {...Uint8Array} parts The arrays.
   * @returns {Uint8Array} Their bytes in order.
   */
  static concat(...parts) {
    const joined = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
    let at = 0;
    for (const part of parts) {
      joined.set(part, at);
      at += part.length;
    }
    return joined;
  }

  /**
   * Writes standard base64 with padding.
   * @param {Uint8Array} bytes The bytes.
   * @returns {string} The base64.
   */
  static encode64(bytes) {
    return UWire.#encode(bytes, UWire.#standard, true);
  }

  /**
   * Writes standard base64 without padding, as ssh-keygen prints a fingerprint.
   * @param {Uint8Array} bytes The bytes.
   * @returns {string} The base64.
   */
  static encodeRaw64(bytes) {
    return UWire.#encode(bytes, UWire.#standard, false);
  }

  /**
   * Writes base64url without padding, as a JWK holds numbers.
   * @param {Uint8Array} bytes The bytes.
   * @returns {string} The base64url.
   */
  static encodeUrl64(bytes) {
    return UWire.#encode(bytes, UWire.#url, false);
  }

  /**
   * Reads standard base64, padded or not; ASCII whitespace is skipped.
   * @param {Uint8Array|string} input The base64, as text or as its ASCII bytes.
   * @returns {Uint8Array} The bytes.
   */
  static decode64(input) {
    return UWire.#decode(input, UWire.#standard);
  }

  /**
   * Reads base64url, padded or not; ASCII whitespace is skipped.
   * @param {Uint8Array|string} input The base64url, as text or as its ASCII bytes.
   * @returns {Uint8Array} The bytes.
   */
  static decodeUrl64(input) {
    return UWire.#decode(input, UWire.#url);
  }

  static #encode(bytes, alphabet, padded) {
    let text = '';
    for (let at = 0; at < bytes.length; at += 3) {
      const rest = bytes.length - at;
      const group = (bytes[at] << 16) | ((rest > 1 ? bytes[at + 1] : 0) << 8) | (rest > 2 ? bytes[at + 2] : 0);
      const digits = Math.min(rest, 3) + 1;
      for (let index = 0; index < 4; index++) {
        if (index < digits) text += alphabet[(group >>> (18 - 6 * index)) & 0x3f];
        else if (padded) text += '=';
      }
    }
    return text;
  }

  static #decode(input, alphabet) {
    const values = UWire.#valuesOf(alphabet);
    const codes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
    const out = new Uint8Array(Math.floor((codes.length * 3) / 4));
    let length = 0;
    let group = 0;
    let digits = 0;
    let padding = 0;
    for (const code of codes) {
      if (code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d) continue;
      if (code === 0x3d) {
        padding++;
        continue;
      }
      const value = code < 0x80 ? values[code] : -1;
      if (value < 0 || padding > 0) throw new RangeError('base64: invalid character');
      group = (group << 6) | value;
      digits++;
      if (digits === 4) {
        out[length++] = group >>> 16;
        out[length++] = group >>> 8;
        out[length++] = group;
        group = 0;
        digits = 0;
      }
    }
    if (digits === 1 || (padding > 0 && (digits < 2 || digits + padding !== 4))) {
      throw new RangeError('base64: invalid length');
    }
    if (digits === 2) out[length++] = group >>> 4;
    if (digits === 3) {
      out[length++] = group >>> 10;
      out[length++] = group >>> 2;
    }
    const bytes = out.slice(0, length);
    out.fill(0);
    return bytes;
  }

  static #valuesOf(alphabet) {
    let values = UWire.#values.get(alphabet);
    if (values === undefined) {
      values = new Int8Array(128).fill(-1);
      for (let index = 0; index < alphabet.length; index++) values[alphabet.charCodeAt(index)] = index;
      UWire.#values.set(alphabet, values);
    }
    return values;
  }
}
