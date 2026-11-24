import { test } from 'node:test';
import assert from 'node:assert/strict';
import { UWire } from '../public/javascript/wire.js';
import * as fixtures from './fixtures.js';

const keys = await fixtures.keys('ED25519', 'ECDSA P-256', 'ECDSA P-384', 'ECDSA P-521', 'RSA 2048');
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const unhex = (text) => new Uint8Array(Buffer.from(text, 'hex'));

// ssh.Marshal(struct{S string; I *big.Int}{"ssh-rsa", v}) of x/crypto v0.59.0, by v in hexadecimal.
const marshalled = [
  ['0', '000000077373682d72736100000000'],
  ['7f', '000000077373682d727361000000017f'],
  ['80', '000000077373682d727361000000020080'],
  ['1ff', '000000077373682d7273610000000201ff'],
  ['9a378f9b2e332a7', '000000077373682d7273610000000809a378f9b2e332a7'],
];

test('wire: a string and an mpint equal the bytes of ssh.Marshal', () => {
  for (const [value, want] of marshalled) {
    const magnitude = unhex(value.padStart(value.length + (value.length % 2), '0'));
    assert.equal(hex(UWire.concat(UWire.string('ssh-rsa'), UWire.mpint(magnitude))), want, value);
  }
});

test('wire: an mpint given with leading zeros is written without them', () => {
  assert.equal(hex(UWire.mpint(unhex('000001ff'))), '0000000201ff');
  assert.equal(hex(UWire.mpint(unhex('000080'))), '000000020080');
  assert.equal(hex(UWire.mpint(unhex('0000'))), '00000000');
});

test('wire: every fixture blob read part by part and written again equals the blob', () => {
  for (const key of keys) {
    const blob = UWire.decode64(key.blob);
    const reader = new UWire(blob);
    const type = reader.text();
    const parts = [UWire.string(type)];
    if (type === 'ssh-rsa') parts.push(UWire.mpint(reader.mpint()), UWire.mpint(reader.mpint()));
    else if (type === 'ssh-ed25519') parts.push(UWire.string(reader.string()));
    else parts.push(UWire.string(reader.text()), UWire.string(reader.string()));
    reader.end();
    assert.equal(hex(UWire.concat(...parts)), hex(blob), key.name);
  }
});

test('wire: a 2048-bit modulus with its high bit set is written with a leading zero byte', () => {
  const key = keys.find((entry) => entry.kind === 'RSA 2048');
  const reader = new UWire(UWire.decode64(key.blob));
  reader.text();
  reader.mpint();
  const n = reader.mpint();
  assert.equal(n.length, 256);
  assert.ok(n[0] >= 0x80);
  assert.equal(hex(UWire.mpint(n)), `00000101${'00'}${hex(n)}`);
});

test('wire: the reader reads every kind of part in order', () => {
  const bytes = UWire.concat(Uint8Array.of(50, 1, 0), UWire.uint32(0xfffffffe), UWire.string('user01'));
  const reader = new UWire(bytes);
  assert.equal(reader.byte(), 50);
  assert.equal(reader.bool(), true);
  assert.equal(reader.bool(), false);
  assert.equal(reader.uint32(), 0xfffffffe);
  assert.equal(reader.text(), 'user01');
  assert.equal(reader.remaining(), 0);
  reader.end();
});

test('wire: the reader refuses short input', () => {
  assert.throws(() => new UWire(Uint8Array.of(0, 0, 0)).uint32(), RangeError);
  assert.throws(() => new UWire(Uint8Array.of(0, 0, 0, 5, 1, 2)).string(), RangeError);
  assert.throws(() => new UWire(new Uint8Array(0)).byte(), RangeError);
});

test('wire: the reader refuses trailing bytes, a negative mpint and text that is not UTF-8', () => {
  const reader = new UWire(Uint8Array.of(1));
  assert.throws(() => reader.end(), RangeError);
  assert.throws(() => new UWire(unhex('0000000180')).mpint(), RangeError);
  assert.throws(() => new UWire(unhex('00000001ff')).text(), TypeError);
});

test('wire: the values read are views, so overwriting the array overwrites them', () => {
  const bytes = UWire.string(Uint8Array.of(1, 2, 3));
  const value = new UWire(bytes).string();
  bytes.fill(0);
  assert.deepEqual([...value], [0, 0, 0]);
});

test('wire: base64, raw base64 and base64url round trip and equal Node encodings', () => {
  for (let length = 0; length < 70; length++) {
    const bytes = Uint8Array.from({ length: length }, (_, index) => (index * 37 + length * 11) & 0xff);
    const buffer = Buffer.from(bytes);
    assert.equal(UWire.encode64(bytes), buffer.toString('base64'));
    assert.equal(UWire.encodeRaw64(bytes), buffer.toString('base64').replace(/=+$/, ''));
    assert.equal(UWire.encodeUrl64(bytes), buffer.toString('base64url'));
    assert.deepEqual(UWire.decode64(UWire.encode64(bytes)), bytes);
    assert.deepEqual(UWire.decode64(UWire.encodeRaw64(bytes)), bytes);
    assert.deepEqual(UWire.decodeUrl64(UWire.encodeUrl64(bytes)), bytes);
  }
});

test('wire: base64 is read from ASCII bytes and across line breaks', () => {
  const text = 'AAEC\r\nAwQF\n  Bg==';
  assert.deepEqual([...UWire.decode64(new TextEncoder().encode(text))], [0, 1, 2, 3, 4, 5, 6]);
});

test('wire: base64 with a foreign character, a lone digit or misplaced padding is refused', () => {
  for (const text of ['AA*A', 'AAAAA', 'A===', 'AA=A', 'AAAA====', '-_AA']) {
    assert.throws(() => UWire.decode64(text), RangeError, text);
  }
  assert.throws(() => UWire.decodeUrl64('+/AA'), RangeError);
  assert.throws(() => UWire.decode64('AAAé'), RangeError);
});

test('wire: base64 skips tabs, and refuses the byte 0x80 and every byte past ASCII', () => {
  assert.deepEqual([...UWire.decode64('AA\tEC')], [0, 1, 2]);
  for (const code of [0x80, 0xc3, 0xff]) {
    assert.throws(() => UWire.decode64(Uint8Array.of(0x41, 0x41, 0x41, code)), RangeError, String(code));
  }
});

test('wire: base64 refuses padding without two digits before it', () => {
  for (const text of ['====', '==', 'AAAA==']) assert.throws(() => UWire.decode64(text), RangeError, text);
});

test('wire: the reader and base64 name each fault in their error', () => {
  const cases = [
    [() => new UWire(Uint8Array.of(0)).bytes(2), 'wire: short input'],
    [() => new UWire(Uint8Array.of(0, 0, 0, 1, 0x80)).mpint(), 'wire: negative mpint'],
    [() => new UWire(Uint8Array.of(0)).end(), 'wire: trailing bytes'],
    [() => UWire.decode64('AA*A'), 'base64: invalid character'],
    [() => UWire.decode64('AAAAA'), 'base64: invalid length'],
  ];
  for (const [read, message] of cases) assert.throws(read, { name: 'RangeError', message: message });
});

test('wire: base64 refuses padding that does not end a group of four', () => {
  for (const text of ['AA=', 'AAA==', 'AA===']) assert.throws(() => UWire.decode64(text), RangeError, text);
  assert.deepEqual([...UWire.decode64('AA==')], [0]);
  assert.deepEqual([...UWire.decode64('AAA=')], [0, 0]);
});

test('wire: base64 decoding overwrites the buffer it decodes into and gives a copy of its bytes', () => {
  const made = [];
  const Native = Uint8Array;
  globalThis.Uint8Array = class extends Native {
    constructor(...args) {
      super(...args);
      made.push(this);
    }
  };
  let bytes;
  try {
    bytes = UWire.decode64('AQIDBAU=');
  } finally {
    globalThis.Uint8Array = Native;
  }
  assert.deepEqual([...bytes], [1, 2, 3, 4, 5]);
  assert.deepEqual(made.map((array) => array === bytes), [false, true]);
  assert.equal(made[0].length, 6);
  assert.ok(made[0].every((byte) => byte === 0));
});

test('wire: base64 builds the table of each alphabet once', () => {
  UWire.decode64('AQID');
  UWire.decodeUrl64('AQID');
  const tables = [];
  const Native = Int8Array;
  globalThis.Int8Array = class extends Native {
    constructor(...args) {
      super(...args);
      tables.push(this);
    }
  };
  try {
    assert.deepEqual([...UWire.decode64('+/8=')], [0xfb, 0xff]);
    assert.deepEqual([...UWire.decodeUrl64('-_8')], [0xfb, 0xff]);
  } finally {
    globalThis.Int8Array = Native;
  }
  assert.deepEqual(tables, []);
});
