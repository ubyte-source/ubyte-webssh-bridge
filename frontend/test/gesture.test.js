import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { UGesture } from '../public/javascript/gesture.js';
import { UStorage } from '../public/javascript/storage.js';

const CELL = { width: 10, height: 20 };

function terminal(selection = '') {
  const calls = { typed: [], focus: 0, sizes: [], scrolled: [], pasted: [] };
  const fake = {
    getKeyBar: () => ({ type: (key) => calls.typed.push(key) }),
    cell: () => CELL,
    focus: () => calls.focus++,
    fontSize: () => 15,
    setFontSize: (size) => calls.sizes.push(size),
    scroll: (lines) => calls.scrolled.push(lines),
    selection: () => selection,
    paste: (text) => calls.pasted.push(text),
  };
  return { gesture: new UGesture(fake), calls: calls };
}

/** The part of an element the gestures use. */
class FakeElement {
  constructor(tag) {
    this.tag = tag;
    this.children = [];
    this.attributes = new Map();
    this.listeners = [];
    this.hidden = false;
    this.properties = new Map();
    this.style = {
      setProperty: (name, value) => this.properties.set(name, value),
    };
  }

  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  setAttribute(name, value) {
    this.attributes.set(name, value);
  }

  addEventListener(type, listener) {
    this.listeners.push([type, listener]);
  }

  append(...children) {
    this.children.push(...children);
  }
}

/** Replaces a global for the rest of the test. */
function replace(t, name, value) {
  const original = Object.getOwnPropertyDescriptor(globalThis, name);
  Object.defineProperty(globalThis, name, { value: value, configurable: true, writable: true });
  t.after(() => (original === undefined ? delete globalThis[name] : Object.defineProperty(globalThis, name, original)));
}

/** Gives the test a document of fake elements and a navigator whose clipboard and vibration it records. */
function browser(t, clipboard = {}) {
  replace(t, 'document', { createElement: (tag) => new FakeElement(tag) });
  const vibrations = [];
  replace(t, 'navigator', { clipboard: clipboard, vibrate: (duration) => vibrations.push(duration) });
  return vibrations;
}

function touch(timeStamp, touches, changed = touches) {
  const list = (points) => points.map(([x, y]) => ({ clientX: x, clientY: y }));
  return {
    timeStamp: timeStamp,
    touches: list(touches),
    changedTouches: list(changed),
    defaultPrevented: false,
    stopPropagation: () => undefined,
    preventDefault() {
      this.defaultPrevented = true;
    },
  };
}

async function gestures() {
  const readme = await readFile(new URL('../../README.md', import.meta.url), 'utf8');
  const lines = readme.split('\n');
  const start = lines.indexOf('| Gesture | Action |') + 2;
  return lines.slice(start, lines.indexOf('', start)).map((line) => line.split(' | ').map((cell) => cell.trim()));
}

test('gesture: a flick right of 30 px within 249 ms is Tab, 29 px or 250 ms is nothing', () => {
  assert.equal(UGesture.classify({ dx: 30, dy: 0, dt: 249 }), 'Tab');
  assert.equal(UGesture.classify({ dx: 29, dy: 0, dt: 249 }), null);
  assert.equal(UGesture.classify({ dx: 30, dy: 0, dt: 250 }), null);
});

test('gesture: a flick left of 30 px within 249 ms is Esc, 29 px or 250 ms is nothing', () => {
  assert.equal(UGesture.classify({ dx: -30, dy: 5, dt: 249 }), 'Esc');
  assert.equal(UGesture.classify({ dx: -29, dy: 5, dt: 249 }), null);
  assert.equal(UGesture.classify({ dx: -30, dy: 5, dt: 250 }), null);
});

test('gesture: a flick up or down of 30 px within 249 ms is an arrow, 29 px or 250 ms is nothing', () => {
  assert.equal(UGesture.classify({ dx: 0, dy: -30, dt: 249 }), '↑');
  assert.equal(UGesture.classify({ dx: 0, dy: 30, dt: 249 }), '↓');
  assert.equal(UGesture.classify({ dx: 0, dy: -29, dt: 249 }), null);
  assert.equal(UGesture.classify({ dx: 0, dy: 29, dt: 249 }), null);
  assert.equal(UGesture.classify({ dx: 0, dy: 30, dt: 250 }), null);
});

test('gesture: a flick that is not mostly horizontal is vertical', () => {
  assert.equal(UGesture.classify({ dx: 40, dy: 40, dt: 100 }), '↓');
  assert.equal(UGesture.classify({ dx: -40, dy: -41, dt: 100 }), '↑');
  assert.equal(UGesture.classify({ dx: 41, dy: -40, dt: 100 }), 'Tab');
});

test('gesture: a drag owes one arrow per whole cell on each axis, less those sent', () => {
  const steps = (dx, dy, sent = { x: 0, y: 0 }) => UGesture.steps({
    dx: dx, dy: dy, cellWidth: CELL.width, cellHeight: CELL.height, sent: sent,
  });
  assert.deepEqual(steps(9.9, 19.9), { x: 0, y: 0 });
  assert.deepEqual(steps(10, 20), { x: 1, y: 1 });
  assert.deepEqual(steps(35, -45), { x: 3, y: -2 });
  assert.deepEqual(steps(-15, 0), { x: -1, y: 0 });
  assert.deepEqual(steps(35, -45, { x: 2, y: -2 }), { x: 1, y: 0 });
  assert.deepEqual(steps(5, 0, { x: 2, y: 0 }), { x: -2, y: 0 });
});

test('gesture: a released flick types its key and a tap focuses the terminal', () => {
  const { gesture, calls } = terminal();
  gesture.begin(touch(0, [[100, 100]]));
  const flick = touch(120, [], [[60, 105]]);
  gesture.end(flick);
  assert.deepEqual(calls.typed, ['Esc']);
  assert.equal(flick.defaultPrevented, true);
  gesture.begin(touch(1000, [[100, 100]]));
  const tap = touch(1080, [], [[103, 102]]);
  gesture.end(tap);
  assert.equal(calls.focus, 1);
  assert.equal(tap.defaultPrevented, false);
});

test('gesture: a finger still down after 250 ms drives the cursor cell by cell as it travels', () => {
  const { gesture, calls } = terminal();
  gesture.begin(touch(0, [[100, 100]]));
  gesture.move(touch(200, [[140, 100]]));
  assert.deepEqual(calls.typed, []);
  gesture.move(touch(260, [[125, 100]]));
  gesture.move(touch(300, [[145, 141]]));
  gesture.move(touch(340, [[95, 141]]));
  gesture.end(touch(400, [], [[95, 141]]));
  assert.deepEqual(calls.typed, ['→', '→', '→', '→', '↓', '↓', '←', '←', '←', '←']);
});

test('gesture: two fingers that spread change the font size, and two that slide scroll', () => {
  const pinch = terminal();
  pinch.gesture.begin(touch(0, [[100, 100], [200, 100]]));
  pinch.gesture.move(touch(50, [[50, 100], [250, 100]]));
  assert.deepEqual(pinch.calls.sizes, [30]);
  const slide = terminal();
  slide.gesture.begin(touch(0, [[100, 100], [200, 100]]));
  slide.gesture.move(touch(50, [[100, 145], [200, 145]]));
  slide.gesture.move(touch(80, [[100, 125], [200, 125]]));
  assert.deepEqual(slide.calls.scrolled, [-2, 1]);
  assert.deepEqual(slide.calls.sizes, []);
});

test("gesture: README's gesture table names every action classify and the handlers produce", async () => {
  const rows = new Map((await gestures()).map(([gesture, action]) => [gesture.slice(2), action]));
  const flick = [...rows.keys()].find((gesture) => gesture.startsWith('Flick right'));
  assert.equal(flick, `Flick right (released within ${UGesture.flickTime} ms, at least ${UGesture.flickDistance} px, `
    + 'mostly horizontal)');
  const vertical = 'Flick up / flick down';
  const flicks = [[{ dx: 30, dy: 0 }, flick], [{ dx: -30, dy: 0 }, 'Flick left'], [{ dx: 0, dy: -30 }, vertical],
    [{ dx: 0, dy: 30 }, vertical]];
  for (const [travel, gesture] of flicks) {
    assert.match(rows.get(gesture), new RegExp(`\`${UGesture.classify({ ...travel, dt: 0 })}\``));
  }
  const drag = rows.get(`One-finger drag (still down after ${UGesture.flickTime} ms)`);
  for (const arrow of ['←', '→', '↑', '↓']) assert.ok(drag.includes(`\`${arrow}\``), arrow);
  assert.match(rows.get('Pinch'), new RegExp(`font size ${UStorage.min}-${UStorage.max}, remembered`));
  const press = rows.get(`Long press (${UGesture.pressTime} ms, moved less than ${UGesture.pressDistance} px)`);
  for (const label of UGesture.menu) assert.ok(press.includes(`\`${label}\``), label);
  assert.ok(rows.has('Tap'));
  assert.ok(rows.has('Two-finger vertical drag'));
  assert.equal(rows.size, 8);
});

test('gesture: attach adds the touch handlers to the ones the element names and listens to the touch events', () => {
  const { gesture } = terminal();
  const handled = new FakeElement('div');
  handled.setAttribute('data-handle-event', 'click:focus');
  const bare = new FakeElement('div');
  assert.equal(gesture.attach(handled), handled);
  assert.equal(gesture.attach(bare), bare);
  const own = 'touchstart:begin touchmove:move touchend:end touchcancel:abort';
  assert.equal(handled.getAttribute('data-handle-event'), `click:focus ${own}`);
  assert.equal(bare.getAttribute('data-handle-event'), own);
  assert.deepEqual(bare.listeners, ['touchstart', 'touchmove', 'touchend', 'touchcancel'].map((type) => [type,
    gesture]));
});

test('gesture: the menu is a hidden backdrop that closes on a click, holding the Paste and Copy buttons', (t) => {
  browser(t);
  const { gesture } = terminal();
  const backdrop = gesture.getMenu();
  assert.equal(gesture.getMenu(), backdrop);
  assert.deepEqual([backdrop.tag, backdrop.className, backdrop.hidden], ['div', 'backdrop', true]);
  assert.equal(backdrop.getAttribute('data-handle-event'), 'click:dismiss');
  assert.deepEqual(backdrop.listeners, [['click', gesture]]);
  const [menu] = backdrop.children;
  assert.deepEqual([menu.tag, menu.className], ['div', 'menu']);
  assert.deepEqual(menu.children.map((button) => [button.tag, button.type, button.textContent,
    button.getAttribute('data-handle-event')]), [['button', 'button', 'Paste', 'click:paste'],
    ['button', 'button', 'Copy', 'click:copy']]);
});

test('gesture: a long press of 500 ms opens the menu at the finger, with Copy only when text is selected', (t) => {
  browser(t);
  t.mock.timers.enable({ apis: ['setTimeout'] });
  for (const [selection, copyHidden] of [['', true], ['user01', false]]) {
    const { gesture, calls } = terminal(selection);
    gesture.begin(touch(0, [[120, 80]]));
    gesture.move(touch(300, [[125, 84]]));
    t.mock.timers.tick(499);
    const menu = gesture.getMenu();
    assert.equal(menu.hidden, true);
    t.mock.timers.tick(1);
    assert.equal(menu.hidden, false);
    assert.deepEqual([...menu.properties], [['--uwsb-menu-x', '120px'], ['--uwsb-menu-y', '80px']]);
    assert.equal(menu.children[0].children[1].hidden, copyHidden);
    gesture.move(touch(600, [[160, 80]]));
    const release = touch(700, [], [[160, 80]]);
    gesture.end(release);
    assert.equal(release.defaultPrevented, true);
    assert.deepEqual([calls.typed, calls.focus], [[], 0]);
    gesture.dismiss();
    assert.equal(menu.hidden, true);
  }
});

test('gesture: a finger that moves 10 px before 500 ms opens no menu, one that moves 9 px does', (t) => {
  browser(t);
  t.mock.timers.enable({ apis: ['setTimeout'] });
  for (const [x, hidden] of [[110, true], [109, false]]) {
    const { gesture } = terminal();
    gesture.begin(touch(0, [[100, 100]]));
    gesture.move(touch(100, [[x, 100]]));
    t.mock.timers.tick(500);
    assert.equal(gesture.getMenu().hidden, hidden, String(x));
  }
});

test('gesture: a cancelled touch opens no menu and its release does nothing', (t) => {
  browser(t);
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { gesture, calls } = terminal();
  const start = touch(0, [[100, 100]]);
  let stopped = 0;
  start.stopPropagation = () => stopped++;
  gesture.begin(start);
  const cancel = touch(10, []);
  cancel.stopPropagation = () => stopped++;
  gesture.abort(cancel);
  t.mock.timers.tick(500);
  assert.equal(gesture.getMenu().hidden, true);
  gesture.move(touch(300, [[160, 100]]));
  const release = touch(320, [], [[60, 100]]);
  gesture.end(release);
  assert.equal(release.defaultPrevented, false);
  assert.deepEqual([calls.typed, calls.focus, stopped], [[], 0, 2]);
});

test('gesture: a touch of three fingers does nothing', () => {
  const { gesture, calls } = terminal();
  const fingers = [[100, 100], [200, 100], [300, 100]];
  gesture.begin(touch(0, fingers));
  gesture.move(touch(300, fingers.map(([x, y]) => [x + 100, y + 100])));
  const release = touch(320, [], fingers);
  gesture.end(release);
  assert.equal(release.defaultPrevented, false);
  assert.deepEqual([calls.typed, calls.focus, calls.sizes, calls.scrolled], [[], 0, [], []]);
});

test('gesture: every touch event stops at the terminal and a move keeps the page from scrolling', () => {
  const { gesture } = terminal();
  const events = [touch(0, [[100, 100]]), touch(10, [[100, 100]]), touch(20, [], [[100, 100]]), touch(30, [])];
  let stopped = 0;
  for (const event of events) event.stopPropagation = () => stopped++;
  gesture.begin(events[0]);
  gesture.move(events[1]);
  gesture.end(events[2]);
  gesture.abort(events[3]);
  assert.equal(stopped, 4);
  assert.equal(events[1].defaultPrevented, true);
});

test('gesture: a tap focuses the terminal only when the finger moved less than 10 px', () => {
  for (const [x, focus] of [[109, 1], [110, 0]]) {
    const { gesture, calls } = terminal();
    gesture.begin(touch(0, [[100, 100]]));
    gesture.end(touch(300, [], [[x, 100]]));
    assert.deepEqual([calls.focus, calls.typed], [focus, []], String(x));
  }
});

test('gesture: a finger drives the cursor from 250 ms on, and its release is no flick', () => {
  for (const [time, typed] of [[249, []], [250, ['→', '→']]]) {
    const { gesture, calls } = terminal();
    gesture.begin(touch(0, [[100, 100]]));
    gesture.move(touch(time, [[125, 100]]));
    const release = touch(time + 1, [], [[160, 100]]);
    gesture.end(release);
    assert.deepEqual(calls.typed, typed, String(time));
    assert.equal(release.defaultPrevented, typed.length > 0, String(time));
  }
});

test('gesture: a key a gesture sends vibrates the phone for 8 ms', (t) => {
  const vibrations = browser(t);
  const { gesture, calls } = terminal();
  gesture.begin(touch(0, [[100, 100]]));
  gesture.end(touch(100, [], [[100, 60]]));
  assert.deepEqual(calls.typed, ['↑']);
  assert.deepEqual(vibrations, [8]);
});

test('gesture: two fingers pinch from 24 px of change and scroll from one cell height of travel', () => {
  for (const [spread, sizes] of [[23, []], [24, [19]]]) {
    const { gesture, calls } = terminal();
    gesture.begin(touch(0, [[100, 100], [200, 100]]));
    gesture.move(touch(50, [[100, 100], [200 + spread, 100]]));
    assert.deepEqual([calls.sizes, calls.scrolled], [sizes, []], String(spread));
  }
  for (const [travel, scrolled] of [[19, []], [20, [-1]]]) {
    const { gesture, calls } = terminal();
    gesture.begin(touch(0, [[100, 100], [200, 100]]));
    gesture.move(touch(50, [[100, 100 + travel], [200, 100 + travel]]));
    assert.deepEqual([calls.scrolled, calls.sizes], [scrolled, []], String(travel));
  }
});

test('gesture: a pinch goes on while both fingers stay and ignores a move of one finger', () => {
  const { gesture, calls } = terminal();
  gesture.begin(touch(0, [[100, 100], [200, 100]]));
  gesture.move(touch(50, [[100, 100], [300, 100]]));
  gesture.move(touch(60, [[100, 100]]));
  gesture.move(touch(70, [[100, 140], [300, 140]]));
  const lift = touch(80, [[100, 140]], [[300, 140]]);
  gesture.end(lift);
  assert.equal(lift.defaultPrevented, true);
  gesture.move(touch(90, [[100, 100], [250, 100]]));
  assert.deepEqual(calls.sizes, [30, 30, 23]);
  assert.deepEqual(calls.scrolled, []);
});

test('gesture: Paste closes the menu and types the clipboard text, and a refused read types nothing', async (t) => {
  let read = Promise.resolve('ls -l\n');
  browser(t, { readText: () => read });
  const { gesture, calls } = terminal();
  const menu = gesture.getMenu();
  menu.hidden = false;
  gesture.paste();
  assert.equal(menu.hidden, true);
  await read;
  read = Promise.reject(new Error('NotAllowedError'));
  gesture.paste();
  await read.catch(() => undefined);
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(calls.pasted, ['ls -l\n']);
});

test('gesture: Copy closes the menu and writes the selection, and a refused write is ignored', async (t) => {
  const written = [];
  let result = Promise.resolve();
  browser(t, {
    writeText: (text) => {
      written.push(text);
      return result;
    },
  });
  const { gesture } = terminal('user01@example.test');
  const menu = gesture.getMenu();
  menu.hidden = false;
  gesture.copy();
  assert.equal(menu.hidden, true);
  result = Promise.reject(new Error('NotAllowedError'));
  gesture.copy();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(written, ['user01@example.test', 'user01@example.test']);
});

test('gesture: a flick is timed from its own touch, however late it starts', () => {
  const { gesture, calls } = terminal();
  gesture.begin(touch(5000, [[100, 100]]));
  gesture.end(touch(5100, [], [[140, 100]]));
  gesture.begin(touch(6000, [[100, 100]]));
  gesture.move(touch(6200, [[140, 100]]));
  gesture.end(touch(6240, [], [[140, 100]]));
  assert.deepEqual(calls.typed, ['Tab', 'Tab']);
});

test('gesture: a second finger stops the long press of the first', (t) => {
  browser(t);
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { gesture } = terminal();
  gesture.begin(touch(0, [[100, 100]]));
  gesture.begin(touch(100, [[100, 100], [200, 100]]));
  t.mock.timers.tick(500);
  assert.equal(gesture.getMenu().hidden, true);
});

test('gesture: once every finger is lifted, a move without a new touch does nothing', () => {
  const { gesture, calls } = terminal();
  gesture.begin(touch(0, [[100, 100]]));
  gesture.end(touch(100, [], [[102, 100]]));
  gesture.move(touch(400, [[160, 100]]));
  const release = touch(450, [], [[160, 100]]);
  gesture.end(release);
  assert.deepEqual([calls.typed, calls.focus, release.defaultPrevented], [[], 1, false]);
});

test('gesture: a drag goes on whatever the time of its later moves, up and down', () => {
  const { gesture, calls } = terminal();
  gesture.begin(touch(1000, [[100, 100]]));
  gesture.move(touch(1300, [[100, 60]]));
  gesture.move(touch(1100, [[100, 100]]));
  assert.deepEqual(calls.typed, ['↑', '↑', '↓', '↓']);
});

test('gesture: a pinch stays a pinch when the fingers then slide together', () => {
  const { gesture, calls } = terminal();
  gesture.begin(touch(0, [[100, 100], [200, 100]]));
  gesture.move(touch(50, [[100, 100], [240, 100]]));
  gesture.move(touch(60, [[100, 160], [200, 160]]));
  assert.deepEqual(calls.sizes, [21, 15]);
  assert.deepEqual(calls.scrolled, []);
});
