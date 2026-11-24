import { test } from 'node:test';
import assert from 'node:assert/strict';
import { UStorage } from '../public/javascript/storage.js';

function memory(entries = {}) {
  const items = new Map(Object.entries(entries));
  return {
    items: items,
    getItem: (name) => items.get(name) ?? null,
    setItem: (name, value) => items.set(name, value),
    removeItem: (name) => items.delete(name),
  };
}

test('storage: uwsb.fontsize is the only key written', () => {
  const store = memory();
  const storage = new UStorage(() => store);
  storage.setFontSize(20);
  storage.setFontSize(8);
  assert.deepEqual([...store.items], [['uwsb.fontsize', '8']]);
  assert.equal(storage.fontSize(15), 8);
});

test('storage: a missing key reads as the default', () => {
  assert.equal(new UStorage(() => memory()).fontSize(15), 15);
});

test('storage: font sizes 8 and 32 read as stored, 7 and 33 as the default', () => {
  for (const [stored, read] of [['8', 8], ['32', 32], ['7', 13], ['33', 13]]) {
    assert.equal(new UStorage(() => memory({ 'uwsb.fontsize': stored })).fontSize(13), read, stored);
  }
});

test('storage: a value that is not a decimal integer reads as the default', () => {
  for (const stored of ['', 'abc', '15.5', '1e1', '+15', '015', ' 15', '15 ', '0x10']) {
    assert.equal(new UStorage(() => memory({ 'uwsb.fontsize': stored })).fontSize(15), 15, stored);
  }
});

test('storage: a throwing storage reads as the default', () => {
  const blocked = new UStorage(() => {
    throw new Error('blocked');
  });
  assert.equal(blocked.fontSize(15), 15);
  const throwing = new UStorage(() => ({
    getItem: () => {
      throw new Error('denied');
    },
  }));
  assert.equal(throwing.fontSize(13), 13);
});

test('storage: a throwing write leaves the page working', () => {
  const full = new UStorage(() => ({
    getItem: () => null,
    setItem: () => {
      throw new Error('quota exceeded');
    },
  }));
  assert.doesNotThrow(() => full.setFontSize(20));
  assert.equal(full.fontSize(15), 15);
  const blocked = new UStorage(() => {
    throw new Error('blocked');
  });
  assert.doesNotThrow(() => blocked.setFontSize(20));
});

test('storage: fits accepts integers from 8 to 32 only', () => {
  assert.deepEqual([7, 8, 32, 33, 15.5, NaN].map((size) => UStorage.fits(size)), [false, true, true, false, false,
    false]);
});

test('storage: a stored size with a sign, spaces, a leading zero or a fraction reads as the default, not as its number',
  () => {
    for (const stored of ['+20', ' 20', '20 ', '020', '20.0', '2e1', '20\n', '\n20']) {
      assert.equal(new UStorage(() => memory({ 'uwsb.fontsize': stored })).fontSize(15), 15, JSON.stringify(stored));
    }
    for (const [stored, size] of [['9', 9], ['10', 10], ['19', 19], ['20', 20], ['29', 29]]) {
      assert.equal(new UStorage(() => memory({ 'uwsb.fontsize': stored })).fontSize(15), size, stored);
    }
  });

test('storage: a font size is written as its decimal text under uwsb.fontsize', () => {
  const store = memory();
  new UStorage(() => store).setFontSize(17);
  assert.equal(store.items.get('uwsb.fontsize'), '17');
});
