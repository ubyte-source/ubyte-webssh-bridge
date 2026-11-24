const encoder = new TextEncoder();

/**
 * One WebSocket to the bridge: binary frames carry terminal bytes, text frames one JSON control message each.
 * The page writes its messages in the protocol's member order and reads only the bridge's messages, member by
 * member within their bounds.
 */
export class UWebSocket {
  static frame = 8192;

  static #members = new Map([
    ['connect', ['user', 'password', 'key', 'cols', 'rows']],
    ['answers', ['answers']],
    ['signature', ['id', 'signature']],
    ['refusal', ['id']],
    ['resize', ['cols', 'rows']],
  ]);

  static #optional = new Set(['password', 'key']);

  static #bridge = new Map([
    ['banner', { text: [true, (value) => UWebSocket.#string(value, 16384)] }],
    ['challenge', {
      name: [true, (value) => UWebSocket.#string(value, 4096)],
      instruction: [true, (value) => UWebSocket.#string(value, 4096)],
      prompts: [true, (value) => Array.isArray(value) && value.length >= 1 && value.length <= 16
        && value.every((prompt) => UWebSocket.#membersOf(prompt, UWebSocket.#prompt))],
    }],
    ['sign', {
      id: [true, (value) => UWebSocket.#integer(value, 1)],
      data: [true, (value) => typeof value === 'string' && value.length > 0 && value.length % 4 === 0
        && /^[A-Za-z0-9+/]*={0,2}$/.test(value)],
      flags: [true, (value) => value === 0 || value === 2 || value === 4],
    }],
    ['ready', {}],
    ['exit', {
      status: [false, (value) => UWebSocket.#integer(value, 0)],
      signal: [false, (value) => UWebSocket.#string(value, 32)],
    }],
  ]);

  static #prompt = {
    text: [true, (value) => UWebSocket.#string(value, 1024)],
    echo: [true, (value) => typeof value === 'boolean'],
  };

  static #texts = new Map([
    [1000, 'Session ended.'],
    [1001, 'The bridge is restarting.'],
    [1008, 'The page and the bridge disagree; reload the page.'],
    [1009, 'A message was too large.'],
    [4002, 'Authentication failed.'],
    [4003, 'The device does not answer.'],
    [4004, 'The device and the bridge share no SSH algorithm, or the device closed the connection.'],
    [4005, 'The login took too long.'],
    [4006, 'The device refused the terminal.'],
    [4007, 'Too many sessions; try again later.'],
    [4008, 'Too many new sessions; wait a moment.'],
    [4009, 'Connection lost.'],
    [4010, 'The connection to the device was lost.'],
  ]);

  #socket;
  #listener;
  #done = false;

  /**
   * Constructs a new UWebSocket instance over a WebSocket and reports its events to the listener.
   * @param {WebSocket} socket The WebSocket, just created.
   * @param {{opened: Function, received: Function, output: Function, closed: Function}} listener Receives this
   *   instance with each event: the open, a control message, terminal bytes and the close code.
   */
  constructor(socket, listener) {
    this.#socket = socket;
    this.#listener = listener;
    socket.binaryType = 'arraybuffer';
    socket.addEventListener('open', () => this.#done || listener.opened(this));
    socket.addEventListener('message', (event) => this.#receive(event));
    socket.addEventListener('close', (event) => this.#finish(event.code));
  }

  /**
   * Returns the WebSocket address of the bridge for the page's address.
   * @param {Location|URL} location The page's address.
   * @returns {string} The `ws:` or `wss:` address of `/ws`.
   */
  static url(location) {
    return new URL('/ws', location.href).href.replace(/^http/, 'ws');
  }

  /**
   * Writes a message of the page, its members in the protocol's order, `password` and `key` omitted when empty.
   * @param {string} type connect, answers, signature, refusal or resize.
   * @param {Object} fields The members.
   * @returns {string} The JSON text.
   */
  static encode(type, fields) {
    const message = { type: type };
    for (const name of UWebSocket.#members.get(type)) {
      const value = fields[name];
      if (UWebSocket.#optional.has(name) && (value ?? '') === '') continue;
      message[name] = value;
    }
    return JSON.stringify(message);
  }

  /**
   * Reads a message of the bridge.
   * @param {string} text The text frame.
   * @returns {Object|null} The message with its type, or null for anything that is not the bridge's.
   */
  static parse(text) {
    let message;
    try {
      message = JSON.parse(text);
    } catch {
      return null;
    }
    if (message === null || typeof message !== 'object' || Array.isArray(message)) return null;
    const schema = UWebSocket.#bridge.get(message.type);
    if (schema === undefined) return null;
    return UWebSocket.#membersOf(message, { type: [true, () => true], ...schema }) ? message : null;
  }

  /**
   * Returns the page's text for a close code; a code without one, 1006 included, reads `Connection lost.`.
   * @param {number} code The close code.
   * @returns {string} The text.
   */
  static text(code) {
    return UWebSocket.#texts.get(code) ?? 'Connection lost.';
  }

  /**
   * Returns the text of a session that ended with 1000, with the exit status or signal the device sent.
   * @param {{status?: number, signal?: string}} exit The exit message, or an empty object.
   * @returns {string} The text.
   */
  static ended({ status, signal }) {
    const parts = [];
    if (status !== undefined) parts.push(`exit status ${status}`);
    if (signal !== undefined) parts.push(`signal ${signal}`);
    if (parts.length === 0) return UWebSocket.text(1000);
    const detail = parts.join(', ');
    return `${UWebSocket.text(1000)} ${detail.charAt(0).toUpperCase()}${detail.slice(1)}.`;
  }

  /**
   * Sends a message of the page.
   * @param {string} type The message type.
   * @param {Object} fields The members.
   */
  send(type, fields) {
    this.#socket.send(UWebSocket.encode(type, fields));
  }

  /**
   * Sends terminal bytes in binary frames of at most 8192 bytes, in order.
   * @param {Uint8Array} bytes The bytes.
   */
  sendInput(bytes) {
    for (let offset = 0; offset < bytes.length; offset += UWebSocket.frame) {
      this.#socket.send(bytes.subarray(offset, offset + UWebSocket.frame));
    }
  }

  /**
   * Closes with 1000; the listener hears nothing more from this connection.
   */
  close() {
    this.#done = true;
    this.#socket.close(1000);
  }

  #receive(event) {
    if (this.#done) return;
    if (typeof event.data !== 'string') {
      this.#listener.output(this, new Uint8Array(event.data));
      return;
    }
    const message = UWebSocket.parse(event.data);
    if (message !== null) {
      this.#listener.received(this, message);
      return;
    }
    // A browser sends only 1000 or 3000-4999: the page closes with 1000 and shows 1008's text.
    this.#socket.close(1000);
    this.#finish(1008);
  }

  #finish(code) {
    if (this.#done) return;
    this.#done = true;
    this.#listener.closed(this, code);
  }

  static #membersOf(object, schema) {
    if (object === null || typeof object !== 'object' || Array.isArray(object)) return false;
    for (const name of Object.keys(object)) if (!Object.hasOwn(schema, name)) return false;
    for (const [name, [required, valid]] of Object.entries(schema)) {
      if (!Object.hasOwn(object, name)) {
        if (required) return false;
        continue;
      }
      if (!valid(object[name])) return false;
    }
    return true;
  }

  static #string(value, bytes) {
    return typeof value === 'string' && encoder.encode(value).length <= bytes;
  }

  static #integer(value, min) {
    return Number.isInteger(value) && value >= min && value <= 0xffffffff;
  }
}
