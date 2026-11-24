import { UHandler } from './handler.js';

/**
 * The touch gestures of the terminal: flicks send Tab, Esc and the vertical arrows, a one-finger drag drives the
 * cursor cell by cell, two fingers scroll or pinch the font size, and a long press opens the Paste and Copy menu.
 */
export class UGesture extends UHandler {
  static flickTime = 250;
  static flickDistance = 30;
  static pressTime = 500;
  static pressDistance = 10;
  static pinchDistance = 24;
  static menu = ['Paste', 'Copy'];

  #terminal;
  #element = {};
  #start = null;
  #mode = null;
  #sent = { x: 0, y: 0 };
  #timer = null;

  /**
   * Constructs a new UGesture instance.
   * @param {UTerminal} terminal The terminal the gestures drive.
   */
  constructor(terminal) {
    super();
    this.#terminal = terminal;
  }

  /**
   * Classifies a released touch as a flick: released within 250 ms, at least 30 px away, right is Tab, left is
   * Esc, and a mostly vertical one is an arrow.
   * @param {{dx: number, dy: number, dt: number}} touch The travel in pixels and the time in milliseconds.
   * @returns {string|null} The key of the bar the flick types, or null.
   */
  static classify({ dx, dy, dt }) {
    if (dt >= UGesture.flickTime) return null;
    if (Math.abs(dx) > Math.abs(dy)) {
      if (Math.abs(dx) < UGesture.flickDistance) return null;
      return dx > 0 ? 'Tab' : 'Esc';
    }
    if (Math.abs(dy) < UGesture.flickDistance) return null;
    return dy < 0 ? '↑' : '↓';
  }

  /**
   * Returns the arrows a drag still owes: one per whole cell travelled on each axis, less those already sent.
   * @param {{dx: number, dy: number, cellWidth: number, cellHeight: number, sent: {x: number, y: number}}} drag
   * @returns {{x: number, y: number}} The signed counts: x positive to the right, y positive downwards.
   */
  static steps({ dx, dy, cellWidth, cellHeight, sent }) {
    return { x: Math.trunc(dx / cellWidth) - sent.x, y: Math.trunc(dy / cellHeight) - sent.y };
  }

  /**
   * Listens to the touches of the element that holds the terminal, beside the events it already handles.
   * @param {HTMLElement} element The element.
   * @returns {HTMLElement} The element.
   */
  attach(element) {
    const own = 'touchstart:begin touchmove:move touchend:end touchcancel:abort';
    const items = [element.getAttribute(UHandler.handle()), own].filter(Boolean);
    element.setAttribute(UHandler.handle(), items.join(' '));
    return this.listen(element, 'touchstart', 'touchmove', 'touchend', 'touchcancel');
  }

  /**
   * Creates or retrieves the long-press menu, over a backdrop that closes it.
   * @returns {HTMLElement} The backdrop holding the menu.
   */
  getMenu() {
    return this.#element.menu ??= this.#menu();
  }

  #menu() {
    const backdrop = document.createElement('div');
    backdrop.className = 'backdrop';
    backdrop.hidden = true;
    backdrop.setAttribute(UHandler.handle(), 'click:dismiss');
    const menu = document.createElement('div');
    menu.className = 'menu';
    const [paste, copy] = UGesture.menu.map((label) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = label;
      button.setAttribute(UHandler.handle(), `click:${label.toLowerCase()}`);
      return button;
    });
    this.#element.copy = copy;
    menu.append(paste, copy);
    backdrop.append(menu);
    return this.listen(backdrop, 'click');
  }

  /**
   * Starts a gesture: one finger starts the long-press timer, two fingers a scroll or a pinch.
   * @param {TouchEvent} event The touchstart event.
   */
  begin(event) {
    event.stopPropagation();
    clearTimeout(this.#timer);
    const touches = event.touches;
    if (touches.length === 1) {
      this.#mode = 'one';
      this.#sent = { x: 0, y: 0 };
      this.#start = { x: touches[0].clientX, y: touches[0].clientY, t: event.timeStamp };
      this.#timer = setTimeout(() => this.#press(), UGesture.pressTime);
      return;
    }
    if (touches.length === 2) {
      this.#mode = 'two';
      this.#start = { ...UGesture.#pair(touches), size: this.#terminal.fontSize(), lines: 0 };
      return;
    }
    this.#mode = null;
  }

  /**
   * Follows a gesture: a drag sends the arrows it owes, two fingers scroll or pinch.
   * @param {TouchEvent} event The touchmove event.
   */
  move(event) {
    event.stopPropagation();
    event.preventDefault();
    switch (this.#mode) {
      case 'one':
      case 'drag':
        this.#drag(event);
        return;
      case 'two':
      case 'scroll':
      case 'pinch':
        if (event.touches.length === 2) this.#two(UGesture.#pair(event.touches));
    }
  }

  /**
   * Ends a gesture: a flick types its key, a tap focuses the terminal.
   * @param {TouchEvent} event The touchend event.
   */
  end(event) {
    event.stopPropagation();
    clearTimeout(this.#timer);
    if (this.#mode === 'one') {
      const touch = event.changedTouches[0];
      const dx = touch.clientX - this.#start.x;
      const dy = touch.clientY - this.#start.y;
      const key = UGesture.classify({ dx: dx, dy: dy, dt: event.timeStamp - this.#start.t });
      if (key !== null) {
        event.preventDefault();
        this.#type(key);
      } else if (Math.hypot(dx, dy) < UGesture.pressDistance) {
        this.#terminal.focus();
      }
    } else if (this.#mode !== null) {
      event.preventDefault();
    }
    if (event.touches.length === 0) this.#mode = null;
  }

  /**
   * Drops a gesture the browser took over.
   * @param {TouchEvent} event The touchcancel event.
   */
  abort(event) {
    event.stopPropagation();
    clearTimeout(this.#timer);
    this.#mode = null;
  }

  /**
   * Pastes the clipboard's text into the terminal.
   */
  paste() {
    this.dismiss();
    navigator.clipboard.readText().then((text) => this.#terminal.paste(text), () => undefined);
  }

  /**
   * Copies the terminal's selection.
   */
  copy() {
    this.dismiss();
    navigator.clipboard.writeText(this.#terminal.selection()).catch(() => undefined);
  }

  /**
   * Closes the long-press menu.
   */
  dismiss() {
    this.getMenu().hidden = true;
  }

  #press() {
    this.#mode = 'press';
    const menu = this.getMenu();
    menu.style.setProperty('--uwsb-menu-x', `${this.#start.x}px`);
    menu.style.setProperty('--uwsb-menu-y', `${this.#start.y}px`);
    this.#element.copy.hidden = this.#terminal.selection() === '';
    menu.hidden = false;
  }

  #drag(event) {
    const touch = event.touches[0];
    const dx = touch.clientX - this.#start.x;
    const dy = touch.clientY - this.#start.y;
    if (Math.hypot(dx, dy) >= UGesture.pressDistance) clearTimeout(this.#timer);
    if (this.#mode === 'one' && event.timeStamp - this.#start.t < UGesture.flickTime) return;
    this.#mode = 'drag';
    const cell = this.#terminal.cell();
    const owed = UGesture.steps({ dx: dx, dy: dy, cellWidth: cell.width, cellHeight: cell.height, sent: this.#sent });
    this.#arrows(owed.x, '→', '←');
    this.#arrows(owed.y, '↓', '↑');
    this.#sent = { x: this.#sent.x + owed.x, y: this.#sent.y + owed.y };
  }

  #arrows(count, forward, backward) {
    for (let step = 0; step < Math.abs(count); step++) this.#type(count > 0 ? forward : backward);
  }

  #two({ distance, y }) {
    if (this.#mode === 'two') {
      if (Math.abs(distance - this.#start.distance) >= UGesture.pinchDistance) {
        this.#mode = 'pinch';
      } else if (Math.abs(y - this.#start.y) >= this.#terminal.cell().height) {
        this.#mode = 'scroll';
      }
    }
    if (this.#mode === 'pinch') {
      this.#terminal.setFontSize(Math.round(this.#start.size * distance / this.#start.distance));
      return;
    }
    if (this.#mode === 'scroll') {
      const lines = Math.trunc((y - this.#start.y) / this.#terminal.cell().height);
      this.#terminal.scroll(this.#start.lines - lines);
      this.#start.lines = lines;
    }
  }

  #type(key) {
    navigator.vibrate?.(8);
    this.#terminal.getKeyBar().type(key);
  }

  static #pair(touches) {
    const a = touches[0];
    const b = touches[1];
    return { distance: Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY), y: (a.clientY + b.clientY) / 2 };
  }
}
