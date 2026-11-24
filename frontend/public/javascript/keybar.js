import { UHandler } from './handler.js';

const ESC = '\x1b';
const CSI = `${ESC}[`;
const SS3 = `${ESC}O`;

/**
 * The extended keys of a phone, in a bar above the on-screen keyboard: pages of keys that ⇄ turns, each whole on
 * a narrow phone, sticky Ctrl and Alt, and the arrows, PgUp, PgDn and Del repeating while held.
 */
export class UKeyBar extends UHandler {
  static pages = [
    ['Esc', 'Tab', 'Ctrl', '←', '↑', '↓', '→', '⇄', '⌨'],
    ['Alt', '|', '/', '-', '~', '⇄', '⌨'],
    ['Home', 'End', 'PgUp', 'PgDn', 'Ins', 'Del', '⇄', '⌨'],
    ['F1', 'F2', 'F3', 'F4', 'F5', 'F6', '⇄', '⌨'],
    ['F7', 'F8', 'F9', 'F10', 'F11', 'F12', '⇄', '⌨'],
  ];

  static repeating = new Set(['←', '↑', '↓', '→', 'PgUp', 'PgDn', 'Del']);
  static lockWindow = 300;
  static repeatDelay = 400;
  static repeatInterval = 60;

  static #cursor = new Map([['↑', 'A'], ['↓', 'B'], ['→', 'C'], ['←', 'D'], ['Home', 'H'], ['End', 'F']]);
  static #tilde = new Map([['Ins', 2], ['Del', 3], ['PgUp', 5], ['PgDn', 6], ['F5', 15], ['F6', 17], ['F7', 18],
    ['F8', 19], ['F9', 20], ['F10', 21], ['F11', 23], ['F12', 24]]);
  static #function = new Map([['F1', 'P'], ['F2', 'Q'], ['F3', 'R'], ['F4', 'S']]);
  static #characters = new Map([['Esc', ESC], ['Tab', '\t'], ['|', '|'], ['/', '/'], ['-', '-'], ['~', '~']]);
  static #controls = new Map([[' ', '\x00'], ['@', '\x00'], ['[', '\x1b'], ['\\', '\x1c'], [']', '\x1d'],
    ['^', '\x1e'], ['_', '\x1f'], ['?', '\x7f']]);

  #terminal;
  #element = {};
  #page = 0;
  #pending = null;
  #timer = null;
  #modifiers = { Ctrl: { armed: false, locked: false, at: 0 }, Alt: { armed: false, locked: false, at: 0 } };

  /**
   * Constructs a new UKeyBar instance.
   * @param {UTerminal} terminal The terminal the keys type into.
   */
  constructor(terminal) {
    super();
    this.#terminal = terminal;
  }

  /**
   * Returns the bytes a key of the bar sends.
   * @param {string} key A key of the bar that types: not Ctrl, Alt, ⇄ or ⌨.
   * @param {{ctrl: boolean, alt: boolean}} modifiers The modifiers held.
   * @param {boolean} applicationCursor True when the remote set the application cursor mode.
   * @returns {string} The sequence.
   */
  static sequence(key, { ctrl, alt }, applicationCursor) {
    const modifier = 1 + (alt ? 2 : 0) + (ctrl ? 4 : 0);
    if (UKeyBar.#cursor.has(key)) {
      const final = UKeyBar.#cursor.get(key);
      if (modifier > 1) return `${CSI}1;${modifier}${final}`;
      return (applicationCursor ? SS3 : CSI) + final;
    }
    if (UKeyBar.#tilde.has(key)) {
      const code = UKeyBar.#tilde.get(key);
      return modifier > 1 ? `${CSI}${code};${modifier}~` : `${CSI}${code}~`;
    }
    if (UKeyBar.#function.has(key)) {
      const final = UKeyBar.#function.get(key);
      return modifier > 1 ? `${CSI}1;${modifier}${final}` : SS3 + final;
    }
    return UKeyBar.modify(UKeyBar.#characters.get(key), { ctrl: ctrl, alt: alt });
  }

  /**
   * Applies Ctrl and Alt to one character: Ctrl turns it into its control character, Alt puts ESC before it.
   * @param {string} character The character.
   * @param {{ctrl: boolean, alt: boolean}} modifiers The modifiers held.
   * @returns {string} The bytes to send, as a string.
   */
  static modify(character, { ctrl, alt }) {
    const typed = ctrl ? UKeyBar.control(character) : character;
    return alt ? ESC + typed : typed;
  }

  /**
   * Returns the control character of a character: a letter's code masked with 0x1f, the punctuation of the C0
   * range, and the character itself when it has none.
   * @param {string} character The character.
   * @returns {string} The control character.
   */
  static control(character) {
    if (/^[A-Za-z]$/.test(character)) return String.fromCharCode(character.charCodeAt(0) & 0x1f);
    return UKeyBar.#controls.get(character) ?? character;
  }

  /**
   * Creates or retrieves the bar with its pages, as many columns wide as the longest page has keys.
   * @returns {HTMLElement} The bar.
   */
  getContainer() {
    return this.#element.container ??= this.#container();
  }

  #container() {
    const container = document.createElement('div');
    container.className = 'keybar';
    container.style.setProperty('--uwsb-keys', String(Math.max(...UKeyBar.pages.map((keys) => keys.length))));
    container.setAttribute(UHandler.handle(),
      'pointerdown:down pointerup:up pointercancel:cancel lostpointercapture:cancel contextmenu:suppress');
    this.listen(container, 'pointerdown', 'pointerup', 'pointercancel', 'lostpointercapture', 'contextmenu');
    this.#element.pages = UKeyBar.pages.map((keys, index) => {
      const page = document.createElement('div');
      page.className = 'page';
      page.hidden = index !== this.#page;
      for (const key of keys) page.append(this.#button(key));
      return page;
    });
    container.append(...this.#element.pages);
    return container;
  }

  #button(key) {
    const button = document.createElement('button');
    button.type = 'button';
    button.tabIndex = -1;
    button.dataset.key = key;
    button.textContent = key;
    if (Object.hasOwn(this.#modifiers, key)) this.#element[key] = button;
    return button;
  }

  /**
   * Types a key of the bar with the modifiers armed or locked, then releases the armed ones.
   * @param {string} key The key.
   */
  type(key) {
    this.#terminal.send(UKeyBar.sequence(key, this.#take(), this.#terminal.applicationCursor()));
  }

  /**
   * Applies the armed or locked modifiers to the text the on-screen keyboard typed: one character only.
   * @param {string} text The text xterm produced.
   * @returns {string} The text to send.
   */
  apply(text) {
    const { ctrl, alt } = this.#held();
    if (!(ctrl || alt) || [...text].length !== 1) return text;
    return UKeyBar.modify(text, this.#take());
  }

  /**
   * Starts a key: a repeating key types at once and again while held, any other key waits for its release. The key
   * captures the pointer, so its release reaches the bar wherever the pointer is.
   * @param {PointerEvent} event The pointerdown event.
   */
  down(event) {
    const key = event.target.closest('button')?.dataset.key;
    if (key === undefined) return;
    event.preventDefault();
    event.target.setPointerCapture(event.pointerId);
    this.#stop();
    if (!UKeyBar.repeating.has(key)) {
      this.#pending = key;
      return;
    }
    const modifiers = this.#take();
    const press = () => this.#terminal.send(UKeyBar.sequence(key, modifiers, this.#terminal.applicationCursor()));
    press();
    this.#timer = setTimeout(() => {
      this.#timer = setInterval(press, UKeyBar.repeatInterval);
    }, UKeyBar.repeatDelay);
  }

  /**
   * Ends a key: a key that waited for its release acts on it.
   * @param {PointerEvent} event The pointerup event.
   */
  up(event) {
    const key = event.target.closest('button')?.dataset.key;
    const pending = this.#pending;
    this.cancel();
    if (key === undefined || key !== pending) return;
    switch (key) {
      case 'Ctrl':
      case 'Alt':
        this.#tap(key);
        return;
      case '⇄':
        this.#turn();
        return;
      case '⌨':
        this.#terminal.keyboard();
        return;
      default:
        this.type(key);
    }
  }

  /**
   * Stops the key held, on a cancel or a lost capture of its pointer: its repeat ends and a waiting key is dropped.
   */
  cancel() {
    this.#stop();
    this.#pending = null;
  }

  /**
   * Keeps the browser's menu off a key held long.
   * @param {Event} event The contextmenu event.
   */
  suppress(event) {
    event.preventDefault();
  }

  /**
   * Stops the key held, releases every modifier and shows the first page.
   */
  reset() {
    this.cancel();
    for (const name of Object.keys(this.#modifiers)) this.#modifiers[name] = { armed: false, locked: false, at: 0 };
    this.#page = 0;
    this.#render();
  }

  #stop() {
    clearTimeout(this.#timer);
    clearInterval(this.#timer);
    this.#timer = null;
  }

  #tap(name) {
    const modifier = this.#modifiers[name];
    const now = performance.now();
    if (modifier.locked) {
      modifier.locked = false;
    } else if (modifier.armed && now - modifier.at < UKeyBar.lockWindow) {
      modifier.armed = false;
      modifier.locked = true;
    } else {
      modifier.armed = !modifier.armed;
      modifier.at = now;
    }
    this.#render();
  }

  #turn() {
    this.#page = (this.#page + 1) % UKeyBar.pages.length;
    this.#render();
  }

  #held() {
    const { Ctrl, Alt } = this.#modifiers;
    return { ctrl: Ctrl.armed || Ctrl.locked, alt: Alt.armed || Alt.locked };
  }

  #take() {
    const held = this.#held();
    for (const modifier of Object.values(this.#modifiers)) modifier.armed = false;
    this.#render();
    return held;
  }

  #render() {
    if (this.#element.container === undefined) return;
    this.#element.pages.forEach((page, index) => {
      page.hidden = index !== this.#page;
    });
    for (const [name, modifier] of Object.entries(this.#modifiers)) {
      this.#element[name].classList.toggle('armed', modifier.armed);
      this.#element[name].classList.toggle('locked', modifier.locked);
    }
  }
}
