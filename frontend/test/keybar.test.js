import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { UKeyBar } from '../public/javascript/keybar.js';

const ESC = '\x1b';
const CSI = `${ESC}[`;
const SS3 = `${ESC}O`;
const NONE = { ctrl: false, alt: false };
const MODIFIERS = [
  [{ ctrl: true, alt: false }, 5],
  [{ ctrl: false, alt: true }, 3],
  [{ ctrl: true, alt: true }, 7],
];

const cursor = { '↑': 'A', '↓': 'B', '→': 'C', '←': 'D', Home: 'H', End: 'F' };
const tilde = { Ins: 2, Del: 3, PgUp: 5, PgDn: 6, F5: 15, F6: 17, F7: 18, F8: 19, F9: 20, F10: 21, F11: 23, F12: 24 };
const functions = { F1: 'P', F2: 'Q', F3: 'R', F4: 'S' };
const characters = { Esc: ESC, Tab: '\t', '|': '|', '/': '/', '-': '-', '~': '~' };

function bar(applicationCursor = false) {
  const sent = [];
  const keyboard = [];
  const terminal = {
    send: (text) => sent.push(text),
    applicationCursor: () => applicationCursor,
    keyboard: () => keyboard.push('toggled'),
  };
  return { keybar: new UKeyBar(terminal), sent: sent, keyboard: keyboard };
}

function key(name) {
  const button = name === undefined ? null : { dataset: { key: name } };
  return {
    pointerId: 7,
    target: {
      captures: [],
      closest: (selector) => (selector === 'button' ? button : null),
      setPointerCapture(id) {
        this.captures.push(id);
      },
    },
    prevented: false,
    preventDefault() {
      this.prevented = true;
    },
  };
}

/** The part of an element the bar uses. */
class FakeElement {
  constructor(tag) {
    this.tag = tag;
    this.children = [];
    this.attributes = new Map();
    this.listeners = [];
    this.dataset = {};
    this.hidden = false;
    this.properties = new Map();
    this.style = {
      setProperty: (name, value) => this.properties.set(name, value),
    };
    this.classes = new Set();
    this.classList = {
      toggle: (name, force) => {
        const on = force ?? !this.classes.has(name);
        if (on) this.classes.add(name);
        else this.classes.delete(name);
      },
    };
  }

  setAttribute(name, value) {
    this.attributes.set(name, value);
  }

  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  addEventListener(type, listener) {
    this.listeners.push([type, listener]);
  }

  append(...children) {
    this.children.push(...children);
  }
}

/** Gives the test a document that creates fake elements. */
function fakeDocument(t) {
  globalThis.document = { createElement: (tag) => new FakeElement(tag) };
  t.after(() => delete globalThis.document);
}

/** Returns the button of a key in the bar. */
function button(container, name) {
  return container.children.flatMap((page) => page.children).find((element) => element.dataset.key === name);
}

/** Returns a pointer event of the given type on a key of the bar, as the browser hands it to the bar. */
function pointer(container, type, name) {
  const event = key(name);
  event.type = type;
  event.target.closest = (selector) => (selector === 'button' ? button(container, name) : container);
  return event;
}

function tap(keybar, name) {
  keybar.down(key(name));
  keybar.up(key(name));
}

test('keybar: cursor keys send CSI in normal mode, SS3 in application mode, CSI 1;m with modifiers', () => {
  for (const [name, final] of Object.entries(cursor)) {
    assert.equal(UKeyBar.sequence(name, NONE, false), `${CSI}${final}`, name);
    assert.equal(UKeyBar.sequence(name, NONE, true), `${SS3}${final}`, name);
    for (const [modifiers, m] of MODIFIERS) {
      for (const mode of [false, true]) {
        assert.equal(UKeyBar.sequence(name, modifiers, mode), `${CSI}1;${m}${final}`, name);
      }
    }
  }
});

test('keybar: editing keys and F5-F12 send CSI n~ in both modes, CSI n;m~ with modifiers', () => {
  for (const [name, code] of Object.entries(tilde)) {
    for (const mode of [false, true]) {
      assert.equal(UKeyBar.sequence(name, NONE, mode), `${CSI}${code}~`, name);
      for (const [modifiers, m] of MODIFIERS) {
        assert.equal(UKeyBar.sequence(name, modifiers, mode), `${CSI}${code};${m}~`, name);
      }
    }
  }
});

test('keybar: F1-F4 send SS3 P-S in both modes, CSI 1;m P-S with modifiers', () => {
  for (const [name, final] of Object.entries(functions)) {
    for (const mode of [false, true]) {
      assert.equal(UKeyBar.sequence(name, NONE, mode), `${SS3}${final}`, name);
      for (const [modifiers, m] of MODIFIERS) {
        assert.equal(UKeyBar.sequence(name, modifiers, mode), `${CSI}1;${m}${final}`, name);
      }
    }
  }
});

test('keybar: Esc, Tab and the symbols send themselves, Ctrl leaves them, Alt puts ESC before them', () => {
  for (const [name, character] of Object.entries(characters)) {
    for (const mode of [false, true]) {
      assert.equal(UKeyBar.sequence(name, NONE, mode), character, name);
      assert.equal(UKeyBar.sequence(name, { ctrl: true, alt: false }, mode), character, name);
      assert.equal(UKeyBar.sequence(name, { ctrl: false, alt: true }, mode), ESC + character, name);
      assert.equal(UKeyBar.sequence(name, { ctrl: true, alt: true }, mode), ESC + character, name);
    }
  }
});

test('keybar: every key of both pages that types has a sequence', () => {
  const typing = UKeyBar.pages.flat().filter((name) => !['Ctrl', 'Alt', '⇄', '⌨'].includes(name));
  for (const name of typing) assert.equal(typeof UKeyBar.sequence(name, NONE, false), 'string', name);
  assert.deepEqual(new Set(typing), new Set([...Object.keys(cursor), ...Object.keys(tilde),
    ...Object.keys(functions), ...Object.keys(characters)]));
});

test('keybar: Ctrl turns letters into code & 0x1f and the C0 punctuation into its control byte', () => {
  for (let code = 0x61; code <= 0x7a; code++) {
    const letter = String.fromCharCode(code);
    assert.equal(UKeyBar.control(letter), String.fromCharCode(code & 0x1f));
    assert.equal(UKeyBar.control(letter.toUpperCase()), String.fromCharCode(code & 0x1f));
  }
  const controls = { ' ': 0x00, '@': 0x00, '[': 0x1b, '\\': 0x1c, ']': 0x1d, '^': 0x1e, '_': 0x1f, '?': 0x7f };
  for (const [character, code] of Object.entries(controls)) {
    assert.equal(UKeyBar.control(character), String.fromCharCode(code), JSON.stringify(character));
  }
  for (const character of ['1', '/', '~', 'é', '\r']) assert.equal(UKeyBar.control(character), character);
});

test('keybar: modify applies Ctrl, then Alt as an ESC prefix', () => {
  assert.equal(UKeyBar.modify('c', NONE), 'c');
  assert.equal(UKeyBar.modify('c', { ctrl: true, alt: false }), '\x03');
  assert.equal(UKeyBar.modify('c', { ctrl: false, alt: true }), `${ESC}c`);
  assert.equal(UKeyBar.modify('c', { ctrl: true, alt: true }), `${ESC}\x03`);
});

test('keybar: a tapped Ctrl applies to one character of the keyboard and is then released', () => {
  const { keybar } = bar();
  tap(keybar, 'Ctrl');
  assert.equal(keybar.apply('ab'), 'ab');
  assert.equal(keybar.apply('c'), '\x03');
  assert.equal(keybar.apply('c'), 'c');
});

test('keybar: a second tap within 300 ms locks Ctrl until it is tapped again', (t) => {
  let now = 1000;
  t.mock.method(performance, 'now', () => now);
  const { keybar } = bar();
  tap(keybar, 'Alt');
  now += 299;
  tap(keybar, 'Alt');
  assert.equal(keybar.apply('x'), `${ESC}x`);
  assert.equal(keybar.apply('x'), `${ESC}x`);
  tap(keybar, 'Alt');
  assert.equal(keybar.apply('x'), 'x');
});

test('keybar: a second tap after 300 ms disarms the modifier', (t) => {
  let now = 1000;
  t.mock.method(performance, 'now', () => now);
  const { keybar } = bar();
  tap(keybar, 'Ctrl');
  now += 300;
  tap(keybar, 'Ctrl');
  assert.equal(keybar.apply('c'), 'c');
});

test('keybar: a key of the bar takes the armed modifiers and releases them', () => {
  const { keybar, sent } = bar();
  tap(keybar, 'Ctrl');
  tap(keybar, 'End');
  tap(keybar, 'End');
  assert.deepEqual(sent, [`${CSI}1;5F`, `${CSI}F`]);
});

test('keybar: a key acts on release, and a cancelled press sends nothing', () => {
  const { keybar, sent } = bar();
  keybar.down(key('Tab'));
  assert.deepEqual(sent, []);
  keybar.cancel();
  keybar.up(key('Tab'));
  assert.deepEqual(sent, []);
  tap(keybar, 'Tab');
  assert.deepEqual(sent, ['\t']);
});

test('keybar: arrows repeat after 400 ms every 60 ms while held, with the modifiers of the press', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  const { keybar, sent } = bar();
  tap(keybar, 'Ctrl');
  keybar.down(key('↑'));
  t.mock.timers.tick(399);
  assert.equal(sent.length, 1);
  t.mock.timers.tick(1);
  for (let round = 0; round < 3; round++) t.mock.timers.tick(60);
  keybar.up(key('↑'));
  t.mock.timers.tick(600);
  assert.deepEqual(sent, Array(4).fill(`${CSI}1;5A`));
  assert.equal(keybar.apply('c'), 'c');
});

test("keybar: README's key-bar table equals the keys of every page", async () => {
  const readme = await readFile(new URL('../../README.md', import.meta.url), 'utf8');
  const lines = readme.split('\n');
  const start = lines.indexOf('| Page | Keys |') + 2;
  const rows = lines.slice(start, lines.indexOf('', start));
  assert.equal(rows.length, UKeyBar.pages.length);
  rows.forEach((row, index) => {
    const cell = row.slice(row.indexOf('|', 1) + 1, row.lastIndexOf('|')).replaceAll('\\|', '|');
    const keys = [];
    for (const [, name, ellipsis] of cell.matchAll(/`([^`]+)`|(…)/g)) {
      if (ellipsis === undefined) {
        keys.push(name);
        continue;
      }
      const first = Number(keys.at(-1).slice(1));
      const last = Number(cell.slice(cell.indexOf('…')).match(/`F(\d+)`/)[1]);
      for (let number = first + 1; number < last; number++) keys.push(`F${number}`);
    }
    assert.deepEqual(keys, UKeyBar.pages[index]);
  });
});

test('keybar: the bar holds every page of keys as buttons, shows the first, and listens to the pointer events',
  (t) => {
    fakeDocument(t);
    const { keybar } = bar();
    const container = keybar.getContainer();
    assert.equal(keybar.getContainer(), container);
    assert.equal(container.tag, 'div');
    assert.equal(container.className, 'keybar');
    assert.deepEqual([...container.attributes], [['data-handle-event',
      'pointerdown:down pointerup:up pointercancel:cancel lostpointercapture:cancel contextmenu:suppress']]);
    assert.deepEqual(container.listeners, ['pointerdown', 'pointerup', 'pointercancel', 'lostpointercapture',
      'contextmenu'].map((type) => [type, keybar]));
    assert.deepEqual(container.children.map((page) => [page.tag, page.className, page.hidden]),
      UKeyBar.pages.map((keys, index) => ['div', 'page', index !== 0]));
    container.children.forEach((page, index) => {
      assert.deepEqual(page.children.map((element) => element.dataset.key), UKeyBar.pages[index]);
      for (const element of page.children) {
        assert.deepEqual([element.tag, element.type, element.tabIndex, element.textContent], ['button', 'button', -1,
          element.dataset.key]);
      }
    });
  });

test('keybar: every page ends with the page and keyboard keys and the bar is as wide as its longest page', (t) => {
  fakeDocument(t);
  const { keybar } = bar();
  const container = keybar.getContainer();
  assert.deepEqual([...container.properties], [['--uwsb-keys', '9']]);
  assert.equal(Math.max(...UKeyBar.pages.map((keys) => keys.length)), 9);
  for (const keys of UKeyBar.pages) assert.deepEqual(keys.slice(-2), ['⇄', '⌨']);
  const typing = UKeyBar.pages.flatMap((keys) => keys.slice(0, -2));
  assert.equal(new Set(typing).size, typing.length);
});

test('keybar: the page key shows each page in turn and then the first again', (t) => {
  fakeDocument(t);
  const { keybar, sent } = bar();
  const pages = keybar.getContainer().children;
  for (let turn = 1; turn <= UKeyBar.pages.length; turn++) {
    tap(keybar, '⇄');
    assert.deepEqual(pages.map((page) => page.hidden), pages.map((page, index) => index !== turn % pages.length));
  }
  assert.deepEqual(sent, []);
});

test('keybar: an armed modifier is highlighted armed, a locked one locked, until a key takes or a tap frees it',
  (t) => {
    fakeDocument(t);
    let now = 1000;
    t.mock.method(performance, 'now', () => now);
    const { keybar } = bar();
    const container = keybar.getContainer();
    const [ctrl, alt] = ['Ctrl', 'Alt'].map((name) => button(container, name));
    tap(keybar, 'Ctrl');
    assert.deepEqual([[...ctrl.classes], [...alt.classes]], [['armed'], []]);
    tap(keybar, 'Alt');
    now += 100;
    tap(keybar, 'Alt');
    assert.deepEqual([[...ctrl.classes], [...alt.classes]], [['armed'], ['locked']]);
    tap(keybar, 'Tab');
    assert.deepEqual([[...ctrl.classes], [...alt.classes]], [[], ['locked']]);
    tap(keybar, 'Alt');
    assert.deepEqual([[...ctrl.classes], [...alt.classes]], [[], []]);
  });

test('keybar: reset releases armed and locked modifiers and shows the first page', (t) => {
  fakeDocument(t);
  let now = 1000;
  t.mock.method(performance, 'now', () => now);
  const { keybar, sent } = bar();
  const container = keybar.getContainer();
  tap(keybar, 'Ctrl');
  tap(keybar, 'Alt');
  now += 100;
  tap(keybar, 'Alt');
  tap(keybar, '⇄');
  keybar.reset();
  assert.deepEqual(container.children.map((page) => page.hidden), UKeyBar.pages.map((keys, index) => index !== 0));
  assert.deepEqual(['Ctrl', 'Alt'].map((name) => [...button(container, name).classes]), [[], []]);
  assert.equal(keybar.apply('c'), 'c');
  now += 100;
  tap(keybar, 'Ctrl');
  assert.equal(keybar.apply('c'), '\x03');
  assert.deepEqual(sent, []);
});

test('keybar: the keyboard key shows or hides the on-screen keyboard and types nothing', () => {
  const { keybar, sent, keyboard } = bar();
  tap(keybar, '⌨');
  tap(keybar, '⌨');
  assert.deepEqual(keyboard, ['toggled', 'toggled']);
  assert.deepEqual(sent, []);
});

test('keybar: a press outside the keys is left to the browser, and a release on another key types nothing', () => {
  const { keybar, sent } = bar();
  const outside = key(undefined);
  keybar.down(outside);
  keybar.up(key(undefined));
  assert.equal(outside.prevented, false);
  const press = key('Tab');
  keybar.down(press);
  assert.equal(press.prevented, true);
  keybar.up(key('Esc'));
  keybar.up(key('Tab'));
  keybar.down(key('Tab'));
  keybar.up(key(undefined));
  assert.deepEqual(sent, []);
});

test('keybar: the context menu of a key held long is suppressed', () => {
  const { keybar } = bar();
  const event = key('Tab');
  keybar.suppress(event);
  assert.equal(event.prevented, true);
});

test('keybar: a key of the bar types in the cursor mode the terminal reports', () => {
  const { keybar, sent } = bar(true);
  tap(keybar, '↑');
  tap(keybar, 'Home');
  assert.deepEqual(sent, [`${SS3}A`, `${SS3}H`]);
});

test('keybar: a held arrow stops repeating when cancelled or when another key is pressed', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  const { keybar, sent } = bar();
  keybar.down(key('←'));
  t.mock.timers.tick(400);
  keybar.cancel();
  t.mock.timers.tick(600);
  assert.deepEqual(sent, [`${CSI}D`]);
  keybar.down(key('→'));
  t.mock.timers.tick(400);
  t.mock.timers.tick(60);
  keybar.down(key('Tab'));
  t.mock.timers.tick(600);
  assert.deepEqual(sent, [`${CSI}D`, `${CSI}C`, `${CSI}C`]);
  keybar.down(key('PgUp'));
  t.mock.timers.tick(399);
  keybar.cancel();
  t.mock.timers.tick(600);
  assert.deepEqual(sent.slice(3), [`${CSI}5~`]);
});

test('keybar: the keyboard text with a modifier held keeps the modifier for one character only', (t) => {
  let now = 1000;
  t.mock.method(performance, 'now', () => now);
  const { keybar } = bar();
  assert.equal(keybar.apply('é'), 'é');
  tap(keybar, 'Alt');
  assert.equal(keybar.apply('xy'), 'xy');
  assert.equal(keybar.apply('é'), `${ESC}é`);
  tap(keybar, 'Ctrl');
  now += 300;
  tap(keybar, 'Ctrl');
  assert.equal(keybar.apply('c'), 'c');
});

test('keybar: the arrows, PgUp, PgDn and Del type on press and repeat, every other key types on release', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  const repeating = ['←', '↑', '↓', '→', 'PgUp', 'PgDn', 'Del'];
  assert.deepEqual([...UKeyBar.repeating], repeating);
  for (const name of UKeyBar.pages.flat().filter((candidate) => !['Ctrl', 'Alt', '⇄', '⌨'].includes(candidate))) {
    const { keybar, sent } = bar();
    keybar.down(key(name));
    t.mock.timers.tick(400);
    t.mock.timers.tick(60);
    keybar.up(key(name));
    const sequence = UKeyBar.sequence(name, NONE, false);
    assert.deepEqual(sent, repeating.includes(name) ? [sequence, sequence] : [sequence], name);
  }
});

test('keybar: a key typed on a fresh bar or after reset leaves Ctrl and Alt unmarked', (t) => {
  fakeDocument(t);
  const { keybar } = bar();
  const container = keybar.getContainer();
  tap(keybar, 'Tab');
  keybar.reset();
  tap(keybar, 'Esc');
  assert.deepEqual(['Ctrl', 'Alt'].map((name) => [...button(container, name).classes]), [[], []]);
});

test('keybar: control leaves a text of more than one character as it is', () => {
  for (const text of ['ab', '1a', 'a1', 'Ab']) assert.equal(UKeyBar.control(text), text);
});

test('keybar: a key pressed captures its pointer, a press outside the keys captures nothing', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  const { keybar } = bar();
  for (const name of ['Tab', 'Del']) {
    const press = key(name);
    keybar.down(press);
    assert.deepEqual(press.target.captures, [7], name);
  }
  const outside = key(undefined);
  keybar.down(outside);
  assert.deepEqual(outside.target.captures, []);
});

test('keybar: a held Del stops repeating on its release, a cancel or a lost capture of its pointer', (t) => {
  fakeDocument(t);
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  const { keybar, sent } = bar();
  const container = keybar.getContainer();
  for (const end of ['pointerup', 'pointercancel', 'lostpointercapture']) {
    sent.length = 0;
    const press = pointer(container, 'pointerdown', 'Del');
    keybar.handleEvent(press);
    assert.deepEqual(press.target.captures, [7], end);
    t.mock.timers.tick(400);
    t.mock.timers.tick(60);
    keybar.handleEvent(pointer(container, end, 'Del'));
    t.mock.timers.tick(600);
    assert.deepEqual(sent, Array(2).fill(`${CSI}3~`), end);
  }
});

test('keybar: reset stops a held key, so neither its repeat nor its release types into the next session', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  const { keybar, sent } = bar();
  keybar.down(key('→'));
  t.mock.timers.tick(400);
  t.mock.timers.tick(60);
  keybar.reset();
  t.mock.timers.tick(600);
  assert.deepEqual(sent, Array(2).fill(`${CSI}C`));
  keybar.down(key('Tab'));
  keybar.reset();
  keybar.up(key('Tab'));
  assert.deepEqual(sent, Array(2).fill(`${CSI}C`));
});
