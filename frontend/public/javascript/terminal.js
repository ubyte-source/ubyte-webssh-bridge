import { Terminal } from './lib/xterm.js';
import { FitAddon } from './lib/addon-fit.js';
import { WebLinksAddon } from './lib/addon-web-links.js';
import { UHandler } from './handler.js';
import { UWebSocket } from './websocket.js';
import { UAuthentication } from './authentication.js';
import { UGesture } from './gesture.js';
import { UKeyBar } from './keybar.js';
import { UStorage } from './storage.js';
import { UKey } from './key.js';
import { UWire } from './wire.js';

const encoder = new TextEncoder();

/**
 * Represents the core terminal interface: xterm with its add-ons, the login card, the connection to the bridge,
 * the key bar and the gestures of a phone, and the views from the login to the end of a session.
 */
export class UTerminal extends UHandler {
  static UWebSocket = UWebSocket;
  static UAuthentication = UAuthentication;
  static UGesture = UGesture;
  static UKeyBar = UKeyBar;
  static UStorage = UStorage;

  static title = 'SSH Web Terminal';
  static question = 'This is a private key. Send it to the device?';
  static cells = 999;

  static #steps = new Map([['=', 1], ['+', 1], ['-', -1], ['0', 0]]);
  static #expected = new Map([
    ['connecting', new Set(['banner', 'challenge', 'sign', 'ready'])],
    ['challenge', new Set()],
    ['terminal', new Set(['exit'])],
  ]);

  #element = {};
  #mount = {};
  #xterm = {};
  #fontSize = null;
  #body = null;
  #socket = null;
  #state = 'login';
  #exit = {};
  #pasted = '';
  #frame = 0;

  /**
   * Initializes a new instance of the UTerminal class with its storage, login flow, gestures and key bar.
   */
  constructor() {
    super();
    this.#mount.storage = new UTerminal.UStorage(() => window.localStorage);
    this.#mount.authentication = new UTerminal.UAuthentication(this);
    this.#mount.gesture = new UTerminal.UGesture(this);
    this.#mount.keybar = new UTerminal.UKeyBar(this);
  }

  /**
   * Tells whether a window runs inside a frame.
   * @param {Window} win The window.
   * @returns {boolean} True when its top window is another one.
   */
  static framed(win) {
    return win.top !== win.self;
  }

  /**
   * Tells whether a link may open: an `http:` or `https:` URL only.
   * @param {string} uri The link.
   * @returns {boolean} True when it may open.
   */
  static linkable(uri) {
    try {
      const { protocol } = new URL(uri);
      return protocol === 'http:' || protocol === 'https:';
    } catch {
      return false;
    }
  }

  /**
   * Bounds a terminal size to the columns and rows the bridge takes.
   * @param {{cols: number, rows: number}} size The size xterm fits.
   * @returns {{cols: number, rows: number}} The size, each from 1 to 999.
   */
  static size({ cols, rows }) {
    const bound = (count) => Math.min(Math.max(count, 1), UTerminal.cells);
    return { cols: bound(cols), rows: bound(rows) };
  }

  /**
   * Opens a link of the terminal in a new tab, without opener and referrer, when it may open.
   * @param {string} uri The link.
   */
  static open(uri) {
    if (UTerminal.linkable(uri)) window.open(uri, '_blank', 'noopener,noreferrer');
  }

  /**
   * Builds the page in the body, unless the page runs inside a frame.
   * @param {HTMLElement} body The body.
   */
  mount(body) {
    if (UTerminal.framed(window)) return;
    this.#body = body;
    body.append(this.getView(), this.getAuthentication().getElement().getContainer());
    new ResizeObserver(() => this.fit()).observe(this.getScreen());
    window.visualViewport.addEventListener('resize', () => this.#viewport());
    window.visualViewport.addEventListener('scroll', () => this.#viewport());
    this.#pointer().addEventListener('change', () => this.#coarse());
    window.addEventListener('dragover', (event) => event.preventDefault());
    window.addEventListener('drop', (event) => event.preventDefault());
    window.addEventListener('paste', (event) => this.getAuthentication().getElement().paste(event));
    this.#viewport();
    this.#coarse();
    this.getAuthentication().getElement().focus();
  }

  /**
   * Instantiates or retrieves the xterm terminal of the connection, open in the screen.
   * @returns {Terminal} The terminal.
   */
  instance() {
    return this.#xterm.terminal ??= this.#terminal();
  }

  #terminal() {
    const terminal = new Terminal({
      cursorBlink: true,
      fontFamily: 'ui-monospace, "SF Mono", Menlo, Consolas, "DejaVu Sans Mono", monospace',
      fontSize: this.fontSize(),
      scrollback: 5000,
      theme: { background: '#222222' },
      linkHandler: { activate: (event, uri) => UTerminal.open(uri) },
    });
    terminal.loadAddon(this.getFitAddon());
    terminal.loadAddon(new WebLinksAddon((event, uri) => UTerminal.open(uri)));
    terminal.onData((text) => this.send(this.getKeyBar().apply(text)));
    terminal.onBinary((text) => {
      this.#input(Uint8Array.from(this.getKeyBar().apply(text), (character) => character.charCodeAt(0)));
    });
    terminal.onResize((size) => {
      if (this.#state === 'terminal') this.#socket.send('resize', UTerminal.size(size));
    });
    terminal.onTitleChange((title) => {
      document.title = title || UTerminal.title;
    });
    terminal.onBell(() => navigator.vibrate?.(30));
    terminal.onSelectionChange(() => {
      if (terminal.hasSelection()) navigator.clipboard.writeText(terminal.getSelection()).catch(() => undefined);
    });
    terminal.attachCustomKeyEventHandler((event) => this.#zoom(event));
    terminal.open(this.getScreen());
    for (const name of ['autocapitalize', 'autocomplete', 'autocorrect']) terminal.textarea.setAttribute(name, 'off');
    terminal.textarea.setAttribute('spellcheck', 'false');
    return terminal;
  }

  /**
   * Retrieves or instantiates the fit add-on of the connection's terminal.
   * @returns {FitAddon} The fit add-on.
   */
  getFitAddon() {
    return this.#xterm.fit ??= new FitAddon();
  }

  /**
   * Retrieves the authentication module.
   * @returns {UAuthentication} The authentication module.
   */
  getAuthentication() {
    return this.#mount.authentication;
  }

  /**
   * Retrieves the gestures.
   * @returns {UGesture} The gestures.
   */
  getGesture() {
    return this.#mount.gesture;
  }

  /**
   * Retrieves the key bar.
   * @returns {UKeyBar} The key bar.
   */
  getKeyBar() {
    return this.#mount.keybar;
  }

  /**
   * Retrieves the storage of the font size.
   * @returns {UStorage} The storage.
   */
  getStorage() {
    return this.#mount.storage;
  }

  /**
   * Creates or retrieves the terminal view: the screen, the key bar, the long-press menu and the dialogs.
   * @returns {HTMLElement} The view element.
   */
  getView() {
    return this.#element.view ??= this.#view();
  }

  #view() {
    const view = document.createElement('div');
    view.className = 'session concealed';
    view.append(this.getScreen(), this.getKeyBar().getContainer(), this.getGesture().getMenu(), this.getOverlay(),
      this.getQuestion());
    return view;
  }

  /**
   * Creates or retrieves the element xterm draws into.
   * @returns {HTMLElement} The screen element.
   */
  getScreen() {
    return this.#element.screen ??= this.#screen();
  }

  #screen() {
    const screen = document.createElement('div');
    screen.className = 'screen';
    screen.setAttribute(UHandler.handle(), 'paste:intercept');
    screen.addEventListener('paste', this, true);
    return this.getGesture().attach(screen);
  }

  /**
   * Creates or retrieves the overlay of a session that ended: its text, Reconnect, New login and Forget key.
   * @returns {HTMLElement} The overlay element.
   */
  getOverlay() {
    return this.#element.overlay ??= this.#overlay();
  }

  #overlay() {
    this.#element.text = UAuthentication.text('p', '', 'text');
    this.#element.reconnect = this.#button('Reconnect', 'click:connect', 'primary');
    this.#element.forget = this.#button('Forget key', 'click:forget');
    return this.#dialog(this.#element.text, this.#element.reconnect, this.#button('New login', 'click:relogin'),
      this.#element.forget);
  }

  /**
   * Creates or retrieves the dialog that asks before a private key is pasted into the terminal.
   * @returns {HTMLElement} The dialog element.
   */
  getQuestion() {
    return this.#element.question ??= this.#question();
  }

  #question() {
    this.#element.refuse = this.#button('Cancel', 'click:refuse keydown:escape');
    return this.#dialog(UAuthentication.text('p', UTerminal.question, 'text'), this.#element.refuse,
      this.#button('Send', 'click:allow keydown:escape', 'primary'));
  }

  #dialog(...children) {
    const part = document.createElement('div');
    part.className = 'parts';
    part.append(...children);
    const overlay = document.createElement('div');
    overlay.className = 'overlay';
    overlay.hidden = true;
    overlay.append(part);
    return overlay;
  }

  #button(text, handle, className = '') {
    const button = UAuthentication.text('button', text, className);
    button.type = 'button';
    button.setAttribute(UHandler.handle(), handle);
    return this.listen(button, 'click', 'keydown');
  }

  /**
   * Opens a connection to the bridge, in a new terminal, with the card's user name and the agent's key: the login and
   * Reconnect.
   */
  connect() {
    this.#exit = {};
    this.#state = 'connecting';
    document.title = UTerminal.title;
    // xterm's reset keeps the output still queued: each connection gets a new terminal.
    this.#xterm.terminal?.dispose();
    this.#xterm = {};
    this.#reveal(false);
    this.getAuthentication().connecting();
    this.#socket = new UTerminal.UWebSocket(new WebSocket(UWebSocket.url(window.location)), this);
  }

  /**
   * Sends the connect message once the WebSocket is open; the agent may sign for this WebSocket only.
   * @param {UWebSocket} socket The connection.
   */
  opened(socket) {
    const { user, password } = this.getAuthentication().credentials();
    const agent = this.getAuthentication().getAgent();
    agent.begin(user);
    const terminal = this.instance();
    this.getFitAddon().fit();
    const { cols, rows } = UTerminal.size(terminal);
    socket.send('connect', {
      user: user,
      password: password,
      key: agent.identity(),
      cols: cols,
      rows: rows,
    });
  }

  /**
   * Acts on a control message of the bridge; one the current view does not expect ends the connection.
   * @param {UWebSocket} socket The connection.
   * @param {Object} message The message.
   */
  received(socket, message) {
    if (!UTerminal.#expected.get(this.#state).has(message.type)) {
      socket.close();
      this.closed(socket, 1008);
      return;
    }
    switch (message.type) {
      case 'banner':
        this.instance().write(message.text.replace(/\r?\n/g, '\r\n'));
        return;
      case 'challenge':
        this.#state = 'challenge';
        this.getAuthentication().challenge(message);
        return;
      case 'sign':
        this.#sign(socket, message);
        return;
      case 'ready':
        this.#ready();
        return;
      default:
        this.#exit = message;
    }
  }

  /**
   * Writes the device's output.
   * @param {UWebSocket} socket The connection.
   * @param {Uint8Array} bytes The bytes.
   */
  output(socket, bytes) {
    this.instance().write(bytes);
  }

  /**
   * Shows how the connection ended: over the terminal after a session, on the card during a login.
   * @param {UWebSocket} socket The connection.
   * @param {number} code The close code.
   */
  closed(socket, code) {
    this.#socket = null;
    const text = code === 1000 ? UWebSocket.ended(this.#exit) : UWebSocket.text(code);
    if (this.#state !== 'terminal') {
      this.#state = 'login';
      this.getAuthentication().idle(text, true);
      return;
    }
    this.#state = 'ended';
    this.instance().blur();
    this.#element.text.textContent = text;
    this.#element.forget.hidden = this.getAuthentication().getAgent().identity() === undefined;
    this.getOverlay().hidden = false;
    this.#element.reconnect.focus();
  }

  /**
   * Ends the connection being opened and shows the card.
   */
  cancel() {
    this.#socket?.close();
    this.#socket = null;
    this.#state = 'login';
    this.getAuthentication().idle('');
  }

  /**
   * Sends the answers of a keyboard-interactive round.
   * @param {string[]} answers The answers.
   */
  answer(answers) {
    this.#socket.send('answers', { answers: answers });
    this.#state = 'connecting';
    this.getAuthentication().connecting();
  }

  /**
   * Returns to the card, the user name kept.
   */
  relogin() {
    this.#state = 'login';
    document.title = UTerminal.title;
    this.#reveal(false);
    this.getAuthentication().idle('');
  }

  /**
   * Drops the key from the agent.
   */
  forget() {
    this.getAuthentication().getKeyZone().forget();
    this.#element.forget.hidden = true;
  }

  /**
   * Holds back a paste of the browser that carries a private key, and asks first.
   * @param {ClipboardEvent} event The paste event, caught before xterm reads it.
   */
  intercept(event) {
    const text = event.clipboardData.getData('text/plain');
    if (!UKey.armoured(text)) return;
    event.preventDefault();
    event.stopPropagation();
    this.#ask(text);
  }

  /**
   * Pastes text into the terminal, asking first when it carries a private key.
   * @param {string} text The text.
   */
  paste(text) {
    if (UKey.armoured(text)) this.#ask(text);
    else this.instance().paste(text);
  }

  /**
   * Pastes the private key held back.
   */
  allow() {
    const text = this.#pasted;
    this.refuse();
    this.instance().paste(text);
  }

  /**
   * Drops the private key held back.
   */
  refuse() {
    this.#pasted = '';
    this.getQuestion().hidden = true;
    this.focus();
  }

  /**
   * Drops the private key held back on Escape.
   * @param {KeyboardEvent} event The keydown event.
   */
  escape(event) {
    if (event.key === 'Escape') this.refuse();
  }

  /**
   * Sends text typed into the terminal.
   * @param {string} text The text.
   */
  send(text) {
    this.#input(encoder.encode(text));
  }

  /**
   * Tells whether the remote set the application cursor mode.
   * @returns {boolean} True in that mode.
   */
  applicationCursor() {
    return this.instance().modes.applicationCursorKeysMode;
  }

  /**
   * Gives the terminal the focus, which opens a phone's keyboard.
   */
  focus() {
    this.instance().focus();
  }

  /**
   * Shows or hides a phone's keyboard.
   */
  keyboard() {
    const area = this.instance().textarea;
    if (document.activeElement === area) area.blur();
    else area.focus();
  }

  /**
   * Returns the size of a character cell.
   * @returns {{width: number, height: number}} The cell's size in CSS pixels.
   */
  cell() {
    const terminal = this.instance();
    const screen = terminal.element.querySelector('.xterm-screen');
    return { width: screen.clientWidth / terminal.cols, height: screen.clientHeight / terminal.rows };
  }

  /**
   * Scrolls the scrollback.
   * @param {number} lines The lines, negative towards the oldest.
   */
  scroll(lines) {
    this.instance().scrollLines(lines);
  }

  /**
   * Returns the selected text.
   * @returns {string} The selection, or empty.
   */
  selection() {
    return this.instance().getSelection();
  }

  /**
   * Returns the font size every terminal of the page takes: the stored one, or the default, until one is set.
   * @returns {number} The font size.
   */
  fontSize() {
    return this.#fontSize ??= this.getStorage().fontSize(this.#size());
  }

  /**
   * Sets the font size within 8-32 and remembers it.
   * @param {number} size The font size.
   */
  setFontSize(size) {
    const fitted = Math.min(UStorage.max, Math.max(UStorage.min, size));
    if (fitted === this.fontSize()) return;
    this.#fontSize = fitted;
    this.instance().options.fontSize = fitted;
    this.getStorage().setFontSize(fitted);
    this.fit();
  }

  /**
   * Fits the terminal to its view at the next frame.
   */
  fit() {
    cancelAnimationFrame(this.#frame);
    this.#frame = requestAnimationFrame(() => this.getFitAddon().fit());
  }

  async #sign(socket, { id, data, flags }) {
    const signature = await this.getAuthentication().getAgent().sign(UWire.decode64(data), flags);
    if (signature === null) socket.send('refusal', { id: id });
    else socket.send('signature', { id: id, signature: UWire.encode64(signature) });
  }

  #ready() {
    this.getAuthentication().getAgent().ready();
    this.#state = 'terminal';
    this.#reveal(true);
    this.getKeyBar().reset();
    this.fit();
    this.focus();
  }

  #reveal(shown) {
    const container = this.getAuthentication().getElement().getContainer();
    this.getView().classList.toggle('concealed', !shown);
    this.getOverlay().hidden = true;
    if (shown) container.remove();
    else if (!container.isConnected) this.#body.append(container);
  }

  #ask(text) {
    this.#pasted = text;
    this.getQuestion().hidden = false;
    this.#element.refuse.focus();
  }

  #input(bytes) {
    if (this.#state === 'terminal') this.#socket.sendInput(bytes);
  }

  #zoom(event) {
    const apple = /Mac|iPhone|iPad|iPod/.test(navigator.platform);
    const step = UTerminal.#steps.get(event.key);
    if (event.type !== 'keydown' || step === undefined || event.altKey) return true;
    if (!(apple ? event.metaKey : event.ctrlKey)) return true;
    event.preventDefault();
    this.setFontSize(step === 0 ? this.#size() : this.fontSize() + step);
    return false;
  }

  #size() {
    return this.#pointer().matches ? 13 : 15;
  }

  #pointer() {
    return this.#mount.pointer ??= window.matchMedia('(pointer: coarse)');
  }

  #coarse() {
    this.getView().classList.toggle('coarse', this.#pointer().matches);
    this.fit();
  }

  #viewport() {
    const viewport = window.visualViewport;
    this.getView().style.setProperty('--uwsb-viewport-height', `${viewport.height}px`);
    this.getView().style.setProperty('--uwsb-viewport-top', `${viewport.offsetTop}px`);
    this.fit();
  }
}
