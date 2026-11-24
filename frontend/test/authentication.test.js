import { test } from 'node:test';
import assert from 'node:assert/strict';
import { UAuthentication } from '../public/javascript/authentication.js';
import * as fixtures from './fixtures.js';

const { UKey } = UAuthentication.UAgent;
const keys = await fixtures.keys('ED25519');
const encode = (text) => new TextEncoder().encode(text);
const plain = keys.find((entry) => entry.name === 'Ed25519 OpenSSH');
const encrypted = keys.find((entry) => entry.name === 'Ed25519 OpenSSH aes128-ctr');

/** The part of an element the login flow uses, in a tree whose events go from the target up to the root. */
class FakeElement {
  constructor(document, tag) {
    this.document = document;
    this.tag = tag;
    this.parentElement = null;
    this.children = [];
    this.attributes = new Map();
    this.listeners = [];
    this.hidden = false;
    this.inert = false;
    this.value = '';
    this.textContent = '';
    this.classList = {
      add: (name) => this.setAttribute('class', [...this.#classes(), name].join(' ')),
      remove: (name) => this.setAttribute('class', this.#classes().filter((other) => other !== name).join(' ')),
      toggle: (name, force) => (force ? this.classList.add(name) : this.classList.remove(name)),
    };
  }

  get className() {
    return this.getAttribute('class') ?? '';
  }

  get isConnected() {
    let element = this;
    while (element.parentElement !== null) element = element.parentElement;
    return element === this.document.body;
  }

  set className(value) {
    this.setAttribute('class', value);
  }

  #classes() {
    return this.className.split(' ').filter(Boolean);
  }

  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  toggleAttribute(name, force) {
    if (force) this.attributes.set(name, '');
    else this.attributes.delete(name);
  }

  addEventListener(type, listener, capture = false) {
    this.listeners.push({ type: type, listener: listener, capture: capture });
  }

  append(...nodes) {
    for (const node of nodes) {
      if (node instanceof FakeElement) {
        node.remove();
        node.parentElement = this;
      }
      this.children.push(node);
    }
  }

  replaceChildren(...nodes) {
    this.children = [];
    this.append(...nodes);
  }

  remove() {
    if (this.parentElement === null) return;
    this.parentElement.children = this.parentElement.children.filter((node) => node !== this);
    this.parentElement = null;
  }

  closest(selector) {
    const name = selector.slice(1, -1);
    for (let element = this; element !== null; element = element.parentElement) {
      if (element.attributes.has(name)) return element;
    }
    return null;
  }

  focus() {
    this.document.activeElement = this;
  }

  click() {
    if (this.getAttribute('form') === null) return;
    const form = this.document.elements.find((element) => element.id === this.getAttribute('form'));
    dispatch(form, { type: 'submit' });
  }
}

/** Gives the test a document of fake elements, which it keeps, and removes it after the test. */
function fakeDocument(t) {
  const document = { elements: [], activeElement: null };
  const create = (tag) => {
    const element = new FakeElement(document, tag);
    document.elements.push(element);
    return element;
  };
  document.createElement = create;
  document.createElementNS = (namespace, tag) => create(tag);
  document.body = create('body');
  globalThis.document = document;
  t.after(() => delete globalThis.document);
  return document;
}

/** Dispatches an event from its target up to the root, capture listeners first, and returns it. */
function dispatch(target, fields) {
  const event = {
    target: target,
    defaultPrevented: false,
    stopped: false,
    preventDefault() {
      this.defaultPrevented = true;
    },
    stopPropagation() {
      this.stopped = true;
    },
    ...fields,
  };
  const path = [];
  for (let element = target; element !== null; element = element.parentElement) path.push(element);
  const phases = [...path.toReversed().map((element) => [element, true]), ...path.map((element) => [element, false])];
  for (const [element, capture] of phases) {
    if (event.stopped) break;
    for (const entry of element.listeners) {
      if (entry.type !== event.type || entry.capture !== capture) continue;
      if (typeof entry.listener === 'function') entry.listener(event);
      else entry.listener.handleEvent(event);
    }
  }
  return event;
}

/** Pastes a text on an element. */
function paste(target, text) {
  const clipboardData = { getData: (format) => (format === 'text/plain' ? text : '') };
  return dispatch(target, { type: 'paste', clipboardData: clipboardData });
}

/** Finds the elements of a tree that a test accepts. */
function find(root, accept) {
  const elements = root.children.filter((node) => node instanceof FakeElement);
  return [...elements.filter(accept), ...elements.flatMap((element) => find(element, accept))];
}

/** Lets the pending promises and timers run. */
async function settle(rounds = 20) {
  for (let round = 0; round < rounds; round++) await new Promise((resolve) => setImmediate(resolve));
}

/** Builds a login flow on the page, which passes every paste to the card, over a terminal that counts. */
function login(t) {
  const document = fakeDocument(t);
  const terminal = { connects: 0, connect: () => terminal.connects++, cancel: () => undefined };
  const authentication = new UAuthentication(terminal);
  const element = authentication.getElement();
  document.body.append(element.getContainer());
  document.body.addEventListener('paste', (event) => element.paste(event));
  element.getUsername().value = 'user01';
  return { authentication: authentication, element: element, terminal: terminal, body: document.body };
}

/** Holds every WebCrypto import until the returned function is called. */
function holdImports(t) {
  const subtle = globalThis.crypto.subtle;
  const importKey = subtle.importKey.bind(subtle);
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const spy = t.mock.method(subtle, 'importKey', async (...args) => {
    await gate;
    return importKey(...args);
  });
  return { spy: spy, release: release };
}

test('authentication: Log In while a pasted key imports locks the card, then connects once with the key',
  async (t) => {
    const { authentication, element, terminal } = login(t);
    const held = holdImports(t);
    const unlock = t.mock.method(UKey.prototype, 'unlock');
    const reading = authentication.getKeyZone().take(encode(plain.text), 'pasted key');
    while (held.spy.mock.callCount() === 0) await settle(1);
    dispatch(element.getForm(), { type: 'submit' });
    dispatch(element.getForm(), { type: 'submit' });
    await settle();
    assert.equal(terminal.connects, 0);
    assert.deepEqual([element.getFields().inert, element.getButton().hidden], [true, true]);
    assert.equal(authentication.getAgent().identity(), undefined);
    held.release();
    await reading;
    await settle();
    assert.equal(terminal.connects, 1);
    assert.equal(unlock.mock.callCount(), 1);
    assert.equal(authentication.getAgent().identity(), plain.blob);
  });

test('authentication: a key that waits for its passphrase is unlocked once by Log In, which then connects',
  async (t) => {
    const { authentication, element, terminal } = login(t);
    const unlock = t.mock.method(UKey.prototype, 'unlock');
    await authentication.getKeyZone().take(encode(encrypted.text), 'id_ed25519');
    assert.equal(element.getPassphrase().hidden, false);
    assert.equal(unlock.mock.callCount(), 0);
    element.getPassphrase().value = encrypted.passphrase;
    dispatch(element.getForm(), { type: 'submit' });
    while (terminal.connects === 0) await settle(1);
    assert.equal(unlock.mock.callCount(), 1);
    assert.equal(authentication.getAgent().identity(), encrypted.blob);
    assert.equal(element.getPassphrase().value, '');
  });

test('authentication: Enter in the passphrase field submits the card through Log In', (t) => {
  const { element } = login(t);
  const click = t.mock.method(element.getButton(), 'click', () => undefined);
  dispatch(element.getPassphrase(), { type: 'keydown', key: 'a' });
  assert.equal(click.mock.callCount(), 0);
  const enter = dispatch(element.getPassphrase(), { type: 'keydown', key: 'Enter' });
  assert.equal(click.mock.callCount(), 1);
  assert.equal(enter.defaultPrevented, true);
});

test('authentication: a private key pasted anywhere while the card is on the page goes to the key zone, once',
  (t) => {
    const { authentication, element, body } = login(t);
    const zone = authentication.getKeyZone();
    const take = t.mock.method(zone, 'take', () => Promise.resolve());
    const forget = find(zone.getChip(), (candidate) => candidate.textContent === 'Forget')[0];
    const targets = [body, element.getButton(), element.getContainer(), element.getUsername(), element.getPassword(),
      element.getPassphrase(), element.getCancel(), forget, zone.getZone()];
    for (const target of targets) assert.equal(paste(target, plain.text).defaultPrevented, true, target.tag);
    assert.equal(take.mock.callCount(), targets.length);
    assert.ok(take.mock.calls.every((call) => call.arguments[1] === 'pasted key'));
    assert.equal(paste(element.getPassword(), 'password-01').defaultPrevented, false);
    assert.equal(take.mock.callCount(), targets.length);
    element.getContainer().remove();
    assert.equal(paste(body, plain.text).defaultPrevented, false);
    assert.equal(take.mock.callCount(), targets.length);
  });

test('authentication: a private key pasted while the card is locked goes nowhere, and the login keeps its key',
  async (t) => {
    const { authentication, element, terminal, body } = login(t);
    const zone = authentication.getKeyZone();
    const held = holdImports(t);
    const reading = zone.take(encode(plain.text), 'pasted key');
    while (held.spy.mock.callCount() === 0) await settle(1);
    const take = t.mock.method(zone, 'take');
    dispatch(element.getForm(), { type: 'submit' });
    assert.equal(element.getStatus().textContent, 'Unlocking key…');
    assert.equal(paste(body, encrypted.text).defaultPrevented, true);
    held.release();
    await reading;
    await settle();
    assert.equal(terminal.connects, 1);
    assert.equal(authentication.getAgent().identity(), plain.blob);
    authentication.connecting();
    assert.equal(paste(body, encrypted.text).defaultPrevented, true);
    authentication.challenge({ name: '', instruction: '', prompts: [{ text: 'Password:', echo: false }] });
    const challenge = element.getContainer().children.at(-1);
    const answers = [...find(challenge, (candidate) => candidate.tag === 'input'),
      ...find(challenge, (candidate) => candidate.tag === 'button'), challenge];
    for (const target of answers) assert.equal(paste(target, encrypted.text).defaultPrevented, true, target.tag);
    assert.equal(paste(answers[0], '123456').defaultPrevented, false);
    assert.equal(take.mock.callCount(), 0);
    assert.equal(authentication.getAgent().identity(), plain.blob);
    authentication.idle('');
    assert.equal(paste(body, encrypted.text).defaultPrevented, true);
    assert.equal(take.mock.callCount(), 1);
  });
