import { UHandler } from './handler.js';
import { UAgent } from './agent.js';

const encoder = new TextEncoder();
const svg = 'http://www.w3.org/2000/svg';

/**
 * The login card: the user name and the password in one form, the key zone, the passphrase of an encrypted key,
 * the status line and the Log In button.
 */
class UElement extends UHandler {
  static armour = 'This is a private key; drop it on the key zone.';

  #authentication;
  #element = {};
  #notes = new Map();

  /**
   * Constructs a new UElement instance.
   * @param {UAuthentication} authentication The authentication this card belongs to.
   */
  constructor(authentication) {
    super();
    this.#authentication = authentication;
  }

  /**
   * Creates or retrieves the title element.
   * @returns {HTMLElement} The title element.
   */
  getTitle() {
    return this.#element.title ??= UAuthentication.text('h5', 'SSH-Authentication');
  }

  /**
   * Creates or retrieves the username input element.
   * @returns {HTMLInputElement} The username input element.
   */
  getUsername() {
    // The names username, secretkey and login_button and the form's class ftnt-fortinet-grid copy FortiGate's
    // login page, so the quick-login tools that fill FortiGate forms fill this card too.
    return this.#element.username ??= this.#input('text', 'Username', {
      name: 'username',
      id: 'username',
      autocomplete: 'username',
      required: '',
      [UHandler.handle()]: 'input:clear',
    });
  }

  /**
   * Creates or retrieves the password input element.
   * @returns {HTMLInputElement} The password input element.
   */
  getPassword() {
    return this.#element.password ??= this.#input('password', 'Password', {
      name: 'secretkey',
      id: 'secretkey',
      autocomplete: 'current-password',
      [UHandler.handle()]: 'input:clear',
    });
  }

  /**
   * Creates or retrieves the passphrase input element: outside the form, so no password manager keeps it.
   * @returns {HTMLInputElement} The passphrase input element.
   */
  getPassphrase() {
    return this.#element.passphrase ??= this.#passphrase();
  }

  #passphrase() {
    const input = this.#input('password', 'Passphrase of the key', {
      autocomplete: 'off',
      [UHandler.handle()]: 'input:clear keydown:enter',
    });
    input.hidden = true;
    this.listen(input, 'keydown');
    return input;
  }

  /**
   * Creates or retrieves the form of the user name and the password.
   * @returns {HTMLFormElement} The form element.
   */
  getForm() {
    return this.#element.form ??= this.#form();
  }

  #form() {
    const form = document.createElement('form');
    form.id = 'login';
    form.className = 'ftnt-fortinet-grid';
    form.setAttribute(UHandler.handle(), 'submit:login');
    form.append(this.getUsername(), this.#note(this.getUsername()), this.getPassword(),
      this.#note(this.getPassword()));
    return this.listen(form, 'submit');
  }

  /**
   * Creates or retrieves the fields the user fills: the form, the key zone and the passphrase.
   * @returns {HTMLElement} The fields element.
   */
  getFields() {
    return this.#element.fields ??= this.#fields();
  }

  #fields() {
    const fields = document.createElement('div');
    fields.className = 'fields';
    fields.append(this.getForm(), this.#authentication.getKeyZone().getContainer(), this.getPassphrase(),
      this.#note(this.getPassphrase()));
    return fields;
  }

  /**
   * Creates or retrieves the status line.
   * @returns {HTMLElement} The status element.
   */
  getStatus() {
    return this.#element.status ??= this.#status();
  }

  #status() {
    const status = document.createElement('p');
    status.className = 'status';
    status.setAttribute('role', 'status');
    return status;
  }

  /**
   * Creates or retrieves the login button element.
   * @returns {HTMLButtonElement} The login button element.
   */
  getButton() {
    return this.#element.button ??= this.#button();
  }

  #button() {
    const button = UAuthentication.text('button', 'Log In');
    button.type = 'submit';
    button.className = 'primary';
    button.id = 'login_button';
    button.name = 'login_button';
    button.setAttribute('form', 'login');
    return button;
  }

  /**
   * Creates or retrieves the button that cancels a connection.
   * @returns {HTMLButtonElement} The cancel button element.
   */
  getCancel() {
    return this.#element.cancel ??= this.#cancel();
  }

  #cancel() {
    const button = UAuthentication.text('button', 'Cancel');
    button.type = 'button';
    button.hidden = true;
    button.setAttribute(UHandler.handle(), 'click:cancel');
    return this.listen(button, 'click');
  }

  /**
   * Creates or retrieves the card.
   * @returns {HTMLElement} The part element.
   */
  getPart() {
    return this.#element.part ??= this.#part();
  }

  #part() {
    const part = document.createElement('div');
    part.className = 'parts';
    part.append(this.getTitle(), this.getFields(), this.getStatus(), this.getButton(), this.getCancel());
    return part;
  }

  /**
   * Creates or retrieves the main container for the authentication UI.
   * @returns {HTMLElement} The container element.
   */
  getContainer() {
    return this.#element.container ??= this.#container();
  }

  #container() {
    const container = document.createElement('div');
    container.className = 'container';
    container.append(this.getPart());
    return container;
  }

  /**
   * Submits the card, unless its fields are locked while the page works.
   * @param {SubmitEvent} event The submit event.
   */
  login(event) {
    event.preventDefault();
    if (!this.getFields().inert) this.#authentication.login();
  }

  /**
   * Hands a private key pasted while the card is on the page to the key zone, whatever has the focus: the page
   * passes it every paste. While the card is locked the key goes nowhere, so the key of a login never changes.
   * @param {ClipboardEvent} event The paste event.
   */
  paste(event) {
    const text = event.clipboardData.getData('text/plain');
    if (!this.getContainer().isConnected || !UAgent.UKey.armoured(text)) return;
    event.preventDefault();
    if (!this.getFields().inert) this.#authentication.getKeyZone().take(encoder.encode(text), 'pasted key');
  }

  /**
   * Clears the note of the field the user types into.
   * @param {InputEvent} event The input event.
   */
  clear(event) {
    this.note(event.target, '');
  }

  /**
   * Submits the card from the passphrase field, which sits outside the form.
   * @param {KeyboardEvent} event The keydown event.
   */
  enter(event) {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    this.getButton().click();
  }

  /**
   * Cancels the connection being opened.
   */
  cancel() {
    this.#authentication.getTerminal().cancel();
  }

  /**
   * Writes the note under a field.
   * @param {HTMLInputElement} input The field.
   * @param {string} text The note, or empty.
   */
  note(input, text) {
    this.#note(input).textContent = text;
  }

  /**
   * Writes the status line.
   * @param {string} text The status, or empty.
   * @param {boolean} [error] True when the status reports a failure.
   */
  status(text, error = false) {
    this.getStatus().textContent = text;
    this.getStatus().classList.toggle('error', error);
  }

  /**
   * Shows or hides the passphrase field, which is emptied when hidden.
   * @param {boolean} shown True to show it.
   */
  passphrase(shown) {
    const input = this.getPassphrase();
    if (!shown) {
      input.value = '';
      this.note(input, '');
    }
    input.hidden = !shown;
  }

  /**
   * Locks the fields while the page works, with the Cancel button when the work can be cancelled.
   * @param {string} text The status.
   * @param {boolean} cancellable True to offer Cancel.
   */
  busy(text, cancellable) {
    this.getFields().inert = true;
    this.getButton().hidden = true;
    this.getCancel().hidden = !cancellable;
    this.status(text);
  }

  /**
   * Unlocks the fields and shows Log In.
   * @param {string} text The status.
   * @param {boolean} [error] True when the status reports a failure.
   */
  idle(text, error = false) {
    this.getFields().inert = false;
    this.getButton().hidden = false;
    this.getCancel().hidden = true;
    this.status(text, error);
  }

  /**
   * Puts the focus on the first field the user still has to fill.
   */
  focus() {
    const passphrase = this.getPassphrase();
    if (!passphrase.hidden) passphrase.focus();
    else if (this.getUsername().value === '') this.getUsername().focus();
    else this.getPassword().focus();
  }

  #input(type, placeholder, attributes) {
    const input = document.createElement('input');
    input.type = type;
    input.placeholder = placeholder;
    input.setAttribute('autocapitalize', 'off');
    input.setAttribute('autocorrect', 'off');
    input.spellcheck = false;
    for (const [attribute, value] of Object.entries(attributes)) input.setAttribute(attribute, value);
    return this.listen(input, 'input');
  }

  #note(input) {
    if (!this.#notes.has(input)) this.#notes.set(input, UAuthentication.text('p', '', 'note'));
    return this.#notes.get(input);
  }
}

/**
 * The key zone: a private key dropped, chosen or pasted is read at once, shown as a chip with its kind and
 * fingerprint, checked against what this browser signs, and imported into the agent, after the passphrase when
 * it has one. The key never leaves the page.
 */
class UKeyZone extends UHandler {
  static limit = 16384;
  static prompt = 'Drop a private key, click to choose it, or paste it';

  #authentication;
  #element = {};
  #key = null;
  #turn = 0;
  #reading = Promise.resolve();

  /**
   * Constructs a new UKeyZone instance.
   * @param {UAuthentication} authentication The authentication this zone belongs to.
   */
  constructor(authentication) {
    super();
    this.#authentication = authentication;
  }

  /**
   * Creates or retrieves the zone with its chip and its message.
   * @returns {HTMLElement} The container element.
   */
  getContainer() {
    return this.#element.container ??= this.#container();
  }

  #container() {
    const container = document.createElement('div');
    container.className = 'key';
    container.append(this.getZone(), this.getFile(), this.getChip(), this.getMessage());
    return container;
  }

  /**
   * Creates or retrieves the box that takes a dropped, chosen or pasted key.
   * @returns {HTMLElement} The zone element.
   */
  getZone() {
    return this.#element.zone ??= this.#zone();
  }

  #zone() {
    const zone = UAuthentication.text('div', UKeyZone.prompt, 'zone');
    zone.tabIndex = 0;
    zone.setAttribute('role', 'button');
    zone.setAttribute(UHandler.handle(),
      'click:choose keydown:press dragenter:over dragover:over dragleave:leave drop:drop paste:paste');
    return this.listen(zone, 'click', 'keydown', 'dragenter', 'dragover', 'dragleave', 'drop', 'paste');
  }

  /**
   * Creates or retrieves the hidden file input behind the zone.
   * @returns {HTMLInputElement} The file input element.
   */
  getFile() {
    return this.#element.file ??= this.#file();
  }

  #file() {
    const input = document.createElement('input');
    input.type = 'file';
    input.hidden = true;
    input.tabIndex = -1;
    input.setAttribute(UHandler.handle(), 'change:pick');
    return this.listen(input, 'change');
  }

  /**
   * Creates or retrieves the chip of the key read: name, kind, fingerprint, comment and Forget.
   * @returns {HTMLElement} The chip element.
   */
  getChip() {
    return this.#element.chip ??= this.#chip();
  }

  #chip() {
    const chip = document.createElement('div');
    chip.className = 'chip';
    chip.hidden = true;
    this.#element.name = UAuthentication.text('p', '', 'name');
    this.#element.lock = this.#lock();
    this.#element.kind = UAuthentication.text('p', '', 'kind');
    this.#element.comment = UAuthentication.text('p', '', 'comment');
    const forget = UAuthentication.text('button', 'Forget');
    forget.type = 'button';
    forget.setAttribute(UHandler.handle(), 'click:forget');
    this.listen(forget, 'click');
    const head = document.createElement('div');
    head.className = 'head';
    head.append(this.#element.lock, this.#element.name, forget);
    chip.append(head, this.#element.kind, this.#element.comment);
    return chip;
  }

  #lock() {
    const icon = document.createElementNS(svg, 'svg');
    icon.setAttribute('viewBox', '0 0 16 16');
    icon.setAttribute('class', 'lock');
    icon.setAttribute('aria-label', 'passphrase needed');
    const body = document.createElementNS(svg, 'rect');
    for (const [name, value] of [['x', 3], ['y', 7], ['width', 10], ['height', 8], ['rx', 1]]) {
      body.setAttribute(name, value);
    }
    const shackle = document.createElementNS(svg, 'path');
    shackle.setAttribute('d', 'M5 7V5a3 3 0 0 1 6 0v2');
    icon.append(body, shackle);
    return icon;
  }

  /**
   * Creates or retrieves the line that tells why a key was refused.
   * @returns {HTMLElement} The message element.
   */
  getMessage() {
    return this.#element.message ??= UAuthentication.text('p', '', 'note');
  }

  /**
   * Returns the key read that waits for its passphrase.
   * @returns {UKey|null} The key, or null.
   */
  pending() {
    return this.#key;
  }

  /**
   * Waits for the key being read: refused, waiting for its passphrase or imported.
   * @returns {Promise<void>} Settles when the read in progress ends.
   */
  read() {
    return this.#reading;
  }

  /**
   * Opens the file chooser.
   */
  choose() {
    this.getFile().click();
  }

  /**
   * Opens the file chooser from the keyboard.
   * @param {KeyboardEvent} event The keydown event.
   */
  press(event) {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    this.choose();
  }

  /**
   * Marks the zone while a file is dragged over it.
   * @param {DragEvent} event The dragenter or dragover event.
   */
  over(event) {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'copy';
    this.getZone().classList.add('over');
  }

  /**
   * Unmarks the zone.
   */
  leave() {
    this.getZone().classList.remove('over');
  }

  /**
   * Reads the file dropped on the zone.
   * @param {DragEvent} event The drop event.
   */
  drop(event) {
    event.preventDefault();
    this.leave();
    const file = event.dataTransfer.files[0];
    if (file !== undefined) this.#reading = this.#read(file);
  }

  /**
   * Reads the file chosen.
   */
  pick() {
    const file = this.getFile().files[0];
    if (file !== undefined) this.#reading = this.#read(file);
  }

  /**
   * Reads the text pasted on the zone as a key; the paste goes no further.
   * @param {ClipboardEvent} event The paste event.
   */
  paste(event) {
    event.preventDefault();
    event.stopPropagation();
    this.take(encoder.encode(event.clipboardData.getData('text/plain')), 'pasted key');
  }

  /**
   * Reads a key: the chip shows it at once, a kind this browser cannot sign with is refused, and a key without
   * passphrase is imported.
   * @param {Uint8Array} bytes The file's bytes, overwritten with zeros once read.
   * @param {string} name The file name, or `pasted key`.
   * @returns {Promise<void>} Settles when the read ends.
   */
  take(bytes, name) {
    this.#reading = this.#take(bytes, name);
    return this.#reading;
  }

  /**
   * Imports the key waiting for its passphrase into the agent; a wrong passphrase keeps the key for another try,
   * any other refusal drops it.
   * @param {Uint8Array} passphrase The passphrase's UTF-8 bytes, overwritten with zeros.
   * @param {function(number, number): void} progress Called with the bcrypt round done and the rounds.
   * @returns {Promise<boolean>} True when the key is loaded.
   */
  unlock(passphrase, progress) {
    return this.#load(this.#key, passphrase, progress);
  }

  async #take(bytes, name) {
    this.forget();
    const turn = this.#turn;
    let key = null;
    try {
      key = await UAgent.UKey.inspect(bytes, name);
      if (!(await UAgent.UKey.signable(key.kind))) throw new UAgent.UKey.Refusal('unsupported', key.kind);
    } catch (error) {
      key?.discard();
      if (turn === this.#turn) this.#refuse(error);
      return;
    }
    if (turn !== this.#turn) {
      key.discard();
      return;
    }
    this.#show(key.name, key.kind, key.fingerprint, key.comment, key.encrypted);
    if (!key.encrypted) {
      await this.#load(key, new Uint8Array(0), () => undefined);
      return;
    }
    this.#key = key;
    this.#authentication.getElement().passphrase(true);
    this.#authentication.getElement().focus();
  }

  async #load(key, passphrase, progress) {
    const turn = this.#turn;
    let loaded;
    try {
      loaded = await key.unlock(passphrase, progress);
    } catch (error) {
      if (turn !== this.#turn) return false;
      if (error.code === 'passphrase') {
        const element = this.#authentication.getElement();
        element.note(element.getPassphrase(), error.text);
        return false;
      }
      this.forget();
      this.#refuse(error);
      return false;
    }
    if (turn !== this.#turn) return false;
    this.#key = null;
    this.#authentication.getAgent().load(loaded.keys, loaded.blob, loaded.kind, loaded.fingerprint);
    this.#authentication.getElement().passphrase(false);
    this.#show('Key loaded', loaded.kind, loaded.fingerprint, this.#element.comment.textContent, false);
    return true;
  }

  /**
   * Drops the key: the one read, the one in the agent, and any read still running.
   */
  forget() {
    this.#turn++;
    this.#key?.discard();
    this.#key = null;
    this.#authentication.getAgent().forget();
    this.#authentication.getElement().passphrase(false);
    this.getChip().hidden = true;
    this.getZone().hidden = false;
    this.getMessage().replaceChildren();
  }

  async #read(file) {
    const input = this.getFile();
    if (file.size > UKeyZone.limit) {
      input.value = '';
      this.forget();
      this.#refuse(new UAgent.UKey.Refusal('too-large'));
      return;
    }
    const bytes = new Uint8Array(await file.arrayBuffer());
    input.value = '';
    await this.#take(bytes, file.name);
  }

  #show(name, kind, fingerprint, comment, locked) {
    this.#element.name.textContent = name;
    this.#element.lock.toggleAttribute('hidden', !locked);
    this.#element.kind.textContent = [kind, fingerprint].filter(Boolean).join(' ');
    this.#element.comment.textContent = comment;
    this.getZone().hidden = true;
    this.getChip().hidden = false;
  }

  #refuse(error) {
    if (!(error instanceof UAgent.UKey.Refusal)) throw error;
    const message = this.getMessage();
    message.replaceChildren(error.text);
    if (error.command) message.append(' ', UAuthentication.text('code', error.command));
  }
}

/**
 * A keyboard-interactive round of the device: its name, its instruction and one field per prompt, a field
 * without echo masked.
 */
class UChallenge extends UHandler {
  #authentication;
  #message;
  #element = {};

  /**
   * Constructs a new UChallenge instance.
   * @param {UAuthentication} authentication The authentication this challenge belongs to.
   * @param {{name: string, instruction: string, prompts: Array<{text: string, echo: boolean}>}} message The
   *   challenge message of the bridge.
   */
  constructor(authentication, message) {
    super();
    this.#authentication = authentication;
    this.#message = message;
  }

  /**
   * Creates or retrieves the fields, one per prompt.
   * @returns {HTMLInputElement[]} The input elements.
   */
  getInputs() {
    return this.#element.inputs ??= this.#message.prompts.map((prompt) => this.#input(prompt));
  }

  #input(prompt) {
    const input = document.createElement('input');
    input.type = prompt.echo ? 'text' : 'password';
    input.setAttribute('autocomplete', 'one-time-code');
    input.setAttribute('autocapitalize', 'off');
    input.setAttribute('autocorrect', 'off');
    input.spellcheck = false;
    input.setAttribute(UHandler.handle(), 'keydown:escape input:clear');
    return this.listen(input, 'keydown', 'input');
  }

  /**
   * Creates or retrieves the note under the fields.
   * @returns {HTMLElement} The note element.
   */
  getNote() {
    return this.#element.note ??= UAuthentication.text('p', '', 'note');
  }

  /**
   * Creates or retrieves the form of the prompts.
   * @returns {HTMLFormElement} The form element.
   */
  getForm() {
    return this.#element.form ??= this.#form();
  }

  #form() {
    const form = document.createElement('form');
    form.setAttribute(UHandler.handle(), 'submit:submit');
    this.#message.prompts.forEach((prompt, index) => {
      const label = document.createElement('label');
      label.append(UAuthentication.text('span', prompt.text), this.getInputs()[index]);
      form.append(label);
    });
    const proceed = UAuthentication.text('button', 'Continue');
    proceed.type = 'submit';
    proceed.className = 'primary';
    proceed.setAttribute(UHandler.handle(), 'keydown:escape');
    const cancel = UAuthentication.text('button', 'Cancel');
    cancel.type = 'button';
    cancel.setAttribute(UHandler.handle(), 'click:cancel keydown:escape');
    this.listen(proceed, 'keydown');
    this.listen(cancel, 'click', 'keydown');
    form.append(this.getNote(), proceed, cancel);
    return this.listen(form, 'submit');
  }

  /**
   * Creates or retrieves the card of the challenge.
   * @returns {HTMLElement} The part element.
   */
  getPart() {
    return this.#element.part ??= this.#part();
  }

  #part() {
    const part = document.createElement('div');
    part.className = 'parts challenge';
    part.append(UAuthentication.text('h5', this.#message.name || 'The device asks'));
    if (this.#message.instruction !== '') {
      part.append(UAuthentication.text('p', this.#message.instruction, 'instruction'));
    }
    part.append(this.getForm());
    return part;
  }

  /**
   * Sends the answers, unless a field holds a private key.
   * @param {SubmitEvent} event The submit event.
   */
  submit(event) {
    event.preventDefault();
    const inputs = this.getInputs();
    if (inputs.some((input) => UAgent.UKey.armoured(input.value))) {
      this.getNote().textContent = UElement.armour;
      return;
    }
    const answers = inputs.map((input) => input.value);
    this.remove();
    this.#authentication.answered(answers);
  }

  /**
   * Ends the session being opened.
   */
  cancel() {
    this.#authentication.getTerminal().cancel();
  }

  /**
   * Cancels on Escape.
   * @param {KeyboardEvent} event The keydown event.
   */
  escape(event) {
    if (event.key === 'Escape') this.cancel();
  }

  /**
   * Clears the note while the user types.
   */
  clear() {
    this.getNote().textContent = '';
  }

  /**
   * Empties the fields and removes the card.
   */
  remove() {
    for (const input of this.getInputs()) input.value = '';
    this.getPart().remove();
  }
}

/**
 * The login flow: the card, the key zone, the keyboard-interactive rounds and the agent that holds the key.
 */
export class UAuthentication {
  static UElement = UElement;
  static UKeyZone = UKeyZone;
  static UChallenge = UChallenge;
  static UAgent = UAgent;

  #terminal;
  #agent;
  #element;
  #zone;
  #challenge = null;

  /**
   * Initializes a new instance of the UAuthentication class.
   * @param {UTerminal} terminal The terminal this authentication logs into.
   */
  constructor(terminal) {
    this.#terminal = terminal;
    this.#agent = new UAuthentication.UAgent();
    this.#element = new UAuthentication.UElement(this);
    this.#zone = new UAuthentication.UKeyZone(this);
  }

  /**
   * Creates an element holding a text.
   * @param {string} tag The tag name.
   * @param {string} text The text.
   * @param {string} [className] The class.
   * @returns {HTMLElement} The element.
   */
  static text(tag, text, className = '') {
    const element = document.createElement(tag);
    element.textContent = text;
    if (className !== '') element.className = className;
    return element;
  }

  /**
   * Retrieves the terminal instance associated with this authentication module.
   * @returns {UTerminal} The terminal instance.
   */
  getTerminal() {
    return this.#terminal;
  }

  /**
   * Retrieves the card.
   * @returns {UElement} The card.
   */
  getElement() {
    return this.#element;
  }

  /**
   * Retrieves the key zone.
   * @returns {UKeyZone} The key zone.
   */
  getKeyZone() {
    return this.#zone;
  }

  /**
   * Retrieves the agent.
   * @returns {UAgent} The agent.
   */
  getAgent() {
    return this.#agent;
  }

  /**
   * Retrieves the username entered by the user.
   * @returns {string} The username.
   */
  getUsername() {
    return this.#element.getUsername().value;
  }

  /**
   * Logs in: refuses a field that holds a private key, locks the card, waits for a key being read, unlocks an
   * encrypted key with its passphrase, then connects.
   */
  async login() {
    const element = this.#element;
    const fields = [element.getUsername(), element.getPassword()];
    const holder = fields.find((input) => UAgent.UKey.armoured(input.value));
    if (holder !== undefined) {
      element.note(holder, UElement.armour);
      return;
    }
    element.busy('Unlocking key…', false);
    await this.#zone.read();
    if (this.#zone.pending() !== null) {
      const field = element.getPassphrase();
      const passphrase = encoder.encode(field.value);
      field.value = '';
      const loaded = await this.#zone.unlock(passphrase, (round, rounds) => {
        element.status(`Unlocking key… ${round} / ${rounds}`);
      });
      if (!loaded) {
        element.idle('');
        element.focus();
        return;
      }
    }
    this.#terminal.connect();
  }

  /**
   * Returns what the connect message sends and empties the password field.
   * @returns {{user: string, password: string}} The user name and the password typed.
   */
  credentials() {
    const password = this.#element.getPassword();
    const login = { user: this.getUsername(), password: password.value };
    password.value = '';
    return login;
  }

  /**
   * Shows the card while the page connects.
   */
  connecting() {
    this.#element.busy('Connecting…', true);
  }

  /**
   * Shows the card ready for a login, with the text of what ended the last attempt.
   * @param {string} text The text, or empty.
   * @param {boolean} [error] True when the text reports a failure.
   */
  idle(text, error = false) {
    this.#dismiss();
    this.#element.idle(text, error);
    this.#element.focus();
  }

  /**
   * Shows a keyboard-interactive round in place of the card.
   * @param {Object} message The challenge message of the bridge.
   */
  challenge(message) {
    this.#dismiss();
    this.#challenge = new UAuthentication.UChallenge(this, message);
    this.#element.getPart().hidden = true;
    this.#element.getContainer().append(this.#challenge.getPart());
    this.#challenge.getInputs()[0].focus();
  }

  /**
   * Sends the answers of the round and shows the card connecting again.
   * @param {string[]} answers The answers, one per prompt.
   */
  answered(answers) {
    this.#challenge = null;
    this.#element.getPart().hidden = false;
    this.#terminal.answer(answers);
  }

  #dismiss() {
    this.#challenge?.remove();
    this.#challenge = null;
    this.#element.getPart().hidden = false;
  }
}
