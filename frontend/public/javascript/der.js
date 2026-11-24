/**
 * The DER the page reads in private key files: an instance reads the elements of one constructed value in order,
 * and `pkcs8` writes the one structure the page builds. Every value an instance reads is a view of its array, so
 * overwriting the array overwrites them.
 */
export class UDer {
  static INTEGER = 0x02;
  static BIT_STRING = 0x03;
  static OCTET_STRING = 0x04;
  static OID = 0x06;
  static SEQUENCE = 0x30;
  static EXPLICIT_0 = 0xa0;
  static EXPLICIT_1 = 0xa1;
  static IMPLICIT_1 = 0x81;

  #bytes;
  #at = 0;

  /**
   * Constructs a new UDer reader.
   * @param {Uint8Array} bytes The contents to read.
   */
  constructor(bytes) {
    this.#bytes = bytes;
  }

  /**
   * Tells whether the next element carries a tag.
   * @param {number} tag The tag byte.
   * @returns {boolean} True when an element follows and its tag is that one.
   */
  next(tag) {
    return this.#at < this.#bytes.length && this.#bytes[this.#at] === tag;
  }

  /**
   * Reads the next element, which must carry a tag.
   * @param {number} tag The tag byte.
   * @returns {Uint8Array} A view of its contents.
   */
  element(tag) {
    if (!this.next(tag)) throw new RangeError('der: unexpected tag');
    this.#at++;
    const length = this.#length();
    if (length > this.#bytes.length - this.#at) throw new RangeError('der: short input');
    const contents = this.#bytes.subarray(this.#at, this.#at + length);
    this.#at += length;
    return contents;
  }

  /**
   * Reads a SEQUENCE.
   * @returns {UDer} A reader of its elements.
   */
  sequence() {
    return new UDer(this.element(UDer.SEQUENCE));
  }

  /**
   * Reads a non-negative INTEGER.
   * @returns {Uint8Array} A view of its magnitude, big-endian, without leading zeros.
   */
  integer() {
    const value = this.element(UDer.INTEGER);
    if (value.length === 0 || value[0] >= 0x80) throw new RangeError('der: invalid integer');
    let start = 0;
    while (start < value.length && value[start] === 0) start++;
    return value.subarray(start);
  }

  /**
   * Reads an OCTET STRING.
   * @returns {Uint8Array} A view of its contents.
   */
  octets() {
    return this.element(UDer.OCTET_STRING);
  }

  /**
   * Reads a BIT STRING of whole bytes.
   * @param {number} [tag] The tag byte, BIT STRING or an implicit one.
   * @returns {Uint8Array} A view of its bytes.
   */
  bits(tag = UDer.BIT_STRING) {
    const value = this.element(tag);
    if (value.length === 0 || value[0] !== 0) throw new RangeError('der: invalid bit string');
    return value.subarray(1);
  }

  /**
   * Reads an OBJECT IDENTIFIER.
   * @returns {string} Its dotted form.
   */
  oid() {
    const value = this.element(UDer.OID);
    if (value.length === 0 || value[value.length - 1] & 0x80) throw new RangeError('der: invalid identifier');
    const arcs = [];
    let arc = 0;
    for (const byte of value) {
      arc = arc * 128 + (byte & 0x7f);
      if (byte & 0x80) continue;
      arcs.push(arc);
      arc = 0;
    }
    const first = Math.min(Math.floor(arcs[0] / 40), 2);
    return [first, arcs[0] - 40 * first, ...arcs.slice(1)].join('.');
  }

  /** Refuses elements left after the last one read. */
  end() {
    if (this.#at !== this.#bytes.length) throw new RangeError('der: trailing bytes');
  }

  /**
   * Writes a PKCS #8 PrivateKeyInfo: version 0, the algorithm and the private key.
   * @param {string[]} identifiers The dotted algorithm identifier and, when it takes one, its parameter's.
   * @param {Uint8Array} key The contents of the privateKey OCTET STRING.
   * @returns {Uint8Array} The DER; the caller overwrites it.
   */
  static pkcs8(identifiers, key) {
    const octets = UDer.write(UDer.OCTET_STRING, key);
    try {
      return UDer.write(
        UDer.SEQUENCE,
        UDer.write(UDer.INTEGER, Uint8Array.of(0)),
        UDer.write(UDer.SEQUENCE, ...identifiers.map((identifier) => UDer.#identifier(identifier))),
        octets,
      );
    } finally {
      octets.fill(0);
    }
  }

  /**
   * Writes one element.
   * @param {number} tag The tag byte.
   * @param {...Uint8Array} parts The contents, in order.
   * @returns {Uint8Array} The element.
   */
  static write(tag, ...parts) {
    const length = parts.reduce((sum, part) => sum + part.length, 0);
    const header = [tag];
    if (length < 0x80) header.push(length);
    else if (length < 0x100) header.push(0x81, length);
    else header.push(0x82, length >>> 8, length & 0xff);
    const element = new Uint8Array(header.length + length);
    element.set(header);
    let at = header.length;
    for (const part of parts) {
      element.set(part, at);
      at += part.length;
    }
    return element;
  }

  #length() {
    if (this.#at >= this.#bytes.length) throw new RangeError('der: short input');
    const first = this.#bytes[this.#at++];
    if (first < 0x80) return first;
    const count = first & 0x7f;
    if (count === 0 || count > 3 || count > this.#bytes.length - this.#at) throw new RangeError('der: invalid length');
    let length = 0;
    for (let index = 0; index < count; index++) length = length * 256 + this.#bytes[this.#at++];
    return length;
  }

  static #identifier(dotted) {
    const [first, second, ...rest] = dotted.split('.').map(Number);
    const bytes = [];
    for (const arc of [40 * first + second, ...rest]) {
      const digits = [arc & 0x7f];
      for (let value = Math.floor(arc / 128); value > 0; value = Math.floor(value / 128)) {
        digits.unshift((value & 0x7f) | 0x80);
      }
      bytes.push(...digits);
    }
    return UDer.write(UDer.OID, Uint8Array.from(bytes));
  }
}
