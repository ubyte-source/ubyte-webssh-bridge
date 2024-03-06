(function (window) {
  "use strict";

  /**
   * A class representation for creating and managing UI elements specifically for authentication purposes.
   */

  class UElement {
    /**
     * Returns the attribute name used for handling events.
     * @returns {string} The attribute name.
     */
    static handle() {
      return "data-handle-event";
    }

    /**
     * Constructs a new UElement instance.
     * @param {Object} authentication The authentication object associated with this element.
     */
    constructor(authentication) {
      this.action = {};
      this.authentication = authentication;
      this.element = {};
    }

    /**
     * Retrieves the authentication object.
     * @returns {Object} The authentication object.
     */
    getAuthentication() {
      return this.authentication;
    }

    /**
     * Sets a callback function for the element.
     * @param {Function} func The callback function to set.
     * @returns {UElement} The instance of this UElement.
     */
    setCallback(func) {
      if (typeof func === "function") this.action.callback = func;
      return this;
    }

    /**
     * Gets the callback function if one is set.
     * @returns {Function|null} The callback function or null if none is set.
     */
    getCallback() {
      return this.action.callback || null;
    }

    /**
     * Creates or retrieves the title element.
     * @returns {HTMLElement} The title element.
     */
    getTitle() {
      if (this.element.hasOwnProperty("title")) return this.element.title;
      this.element.title = document.createElement("h5");
      this.element.title.innerText = "SSH-Authentication";
      return this.element.title;
    }

    /**
     * Creates or retrieves the username input element.
     * @returns {HTMLElement} The username input element.
     */
    getUsername() {
      if (this.element.hasOwnProperty("username")) return this.element.username;
      this.element.username = document.createElement("input");
      this.element.username.type = "text";
      this.element.username.setAttribute("placeholder", "Username");
      this.element.username.setAttribute("autocapitalize", "off");
      this.element.username.setAttribute("autocorrect", "off");
      this.element.username.setAttribute("name", "username");
      this.element.username.setAttribute("id", "username");
      return this.element.username;
    }

    /**
     * Creates or retrieves the password input element.
     * @returns {HTMLElement} The password input element.
     */
    getPassword() {
      if (this.element.hasOwnProperty("password")) return this.element.password;
      this.element.password = document.createElement("input");
      this.element.password.type = "password";
      this.element.password.setAttribute("placeholder", "Password");
      this.element.password.setAttribute("autocomplete", "off");
      this.element.password.setAttribute("name", "secretkey");
      this.element.password.setAttribute("id", "secretkey");
      return this.element.password;
    }

    /**
     * Creates or retrieves the login button element.
     * @returns {HTMLElement} The login button element.
     */
    getButton() {
      if (this.element.hasOwnProperty("button")) return this.element.button;
      this.element.button = document.createElement("button");
      this.element.button.type = "submit";
      this.element.button.innerText = "Log In";
      this.element.button.setAttribute(this.constructor.handle(), ":login");
      this.element.button.addEventListener("click", this, true);
      this.element.button.setAttribute("id", "login_button");
      return this.element.button;
    }

    /**
     * Creates or retrieves the part div that groups form elements.
     * @returns {HTMLElement} The part div element.
     */
    getPart() {
      if (this.element.hasOwnProperty("part")) return this.element.part;
      this.element.part = document.createElement("div");
      this.element.part.className = "parts";
      this.element.part.appendChild(this.getTitle());
      this.element.part.appendChild(this.getForm());
      return this.element.part;
    }

    /**
     * Creates or retrieves the form element that contains input fields and button.
     * @returns {HTMLElement} The form element.
     */
    getForm() {
      if (this.element.hasOwnProperty("form")) return this.element.form;
      this.element.form = document.createElement("form");
      this.element.form.className = "login ftnt-fortinet-grid";
      this.element.form.appendChild(this.getUsername());
      this.element.form.appendChild(this.getPassword());
      this.element.form.appendChild(this.getButton());
      return this.element.form;
    }

    /**
     * Creates or retrieves the main container for the authentication UI.
     * @returns {HTMLElement} The container element.
     */
    getContainer() {
      if (this.element.hasOwnProperty("container"))
        return this.element.container;
      this.element.container = document.createElement("div");
      this.element.container.className = "container";
      this.element.container.appendChild(this.getPart());
      return this.element.container;
    }

    /**
     * Handles the login action, preventing the default form submission and calling the callback function.
     * @param {Event} event The event object.
     */
    login(event) {
      event.preventDefault();
      const callback = this.getCallback();
      if (typeof callback === "function") callback.call(this, event);
    }

    /**
     * Delegates event handling to the appropriate method based on the event type and attribute.
     * @param {Event} event The event object.
     */
    handleEvent(event) {
      let attribute = this.constructor.closestAttribute(
        event.target,
        this.constructor.handle()
      );
      if (attribute === null) return;

      let attribute_split = attribute.split(/\s+/);
      for (let item = 0; item < attribute_split.length; item++) {
        let execute = attribute_split[item].split(String.fromCharCode(58));
        if (execute.length !== 2) break;
        if (execute[0] === event.type || 0 === execute[0].length) {
          if (typeof this[execute[1]] !== "function") continue;

          this[execute[1]].call(this, event);
        }
      }
    }

    /**
     * Finds the closest ancestor of the target element that has the specified attribute.
     * @param {HTMLElement} target The target element.
     * @param {string} attribute The attribute name to search for.
     * @param {boolean} html If true, returns the HTML of the element.
     * @returns {string|null} The value of the attribute or null if not found.
     */
    static closestAttribute(target, attribute, html) {
      if (typeof attribute === "undefined" || !attribute.length) return null;

      let result = null,
        element = target;

      do {
        let tagname = element.tagName.toLowerCase();
        if (tagname === "body") return null;

        result = element.getAttribute(attribute);
        if (result !== null) {
          result = result.toString();
          if (result.length) break;
        }

        element = element.parentNode;
      } while (element !== null || typeof element === "undefined");

      if (typeof html === "undefined" || html !== true) return result;

      return element;
    }

    /**
     * Removes an element from the DOM.
     * @param {HTMLElement} element The element to remove.
     * @returns {boolean} True if the element was removed, false otherwise.
     */
    static removeElementDOM(element) {
      let parent =
        element === null ||
        typeof element === "undefined" ||
        typeof element.parentNode === "undefined"
          ? null
          : element.parentNode;
      if (parent === null) return false;
      parent.removeChild(element);
      return true;
    }
  }

  /**
   * Represents the authentication module within the terminal application.
   * This class is responsible for managing user authentication, including
   * capturing user credentials and handling the authentication process.
   */
  class UAuthentication {
    /**
     * Initializes a new instance of the UAuthentication class.
     * @param {UTerminal} terminal The terminal instance that this authentication module is associated with.
     */
    constructor(terminal) {
      this.terminal = terminal;

      // Initializes a new UElement instance, passing this authentication instance to it.
      // This allows the UElement to use authentication-related functionalities and properties.

      this.element = new window.Terminal.UTerminal.UAuthentication.UElement(
        this
      );
    }

    /**
     * Retrieves the terminal instance associated with this authentication module.
     * @returns {UTerminal} The terminal instance.
     */
    getTerminal() {
      return this.terminal;
    }

    /**
     * Retrieves the UElement instance associated with this authentication module.
     * This instance is used to manage the UI elements related to authentication.
     * @returns {UElement} The UElement instance managing authentication UI elements.
     */
    getElement() {
      return this.element;
    }

    /**
     * Retrieves the username entered by the user in the authentication UI.
     * This method delegates to the UElement instance to access the input element directly.
     * @returns {string} The username entered by the user.
     */
    getUsername() {
      // Uses the UElement instance to get the username input element and return its current value.
      return this.getElement().getUsername().value;
    }

    /**
     * Retrieves the password entered by the user in the authentication UI.
     * Similar to getUsername, this method delegates to the UElement instance.
     * @returns {string} The password entered by the user.
     */
    getPassword() {
      // Uses the UElement instance to get the password input element and return its current value.
      return this.getElement().getPassword().value;
    }
  }

  /**
   * Manages WebSocket connections for the terminal application.
   * This class is responsible for setting up and maintaining the WebSocket connection,
   * allowing for real-time communication between the client and server.
   */
  class UWebSocket {
    /**
     * Initializes a new instance of the UWebSocket class.
     * @param {UTerminal} terminal The terminal instance associated with this WebSocket connection.
     */
    constructor(terminal) {
      this.terminal = terminal;
      // Initialize an empty object to store WebSocket configuration and state.
      this.socket = {};
      this.socket.attribute = {};
    }

    /**
     * Retrieves the terminal instance associated with this WebSocket connection.
     * @returns {UTerminal} The terminal instance.
     */
    getTerminal() {
      return this.terminal;
    }

    /**
     * Sets the URI for the WebSocket connection.
     * @param {string} value The URI to connect to.
     * @returns {UWebSocket} Returns the instance of this UWebSocket for method chaining.
     */
    setUri(value) {
      this.socket.attribute.uri = value;
      // After setting the URI, automatically attempt to generate (and potentially open) the WebSocket connection.
      this.generate();
      return this;
    }

    /**
     * Retrieves the URI configured for the WebSocket connection.
     * @returns {string} The URI of the WebSocket connection.
     */
    getUri() {
      return this.socket.attribute.uri;
    }

    /**
     * Retrieves the WebSocket instance.
     * If the WebSocket has not been initialized, this method returns null.
     * @returns {WebSocket|null} The WebSocket instance or null if it hasn't been initialized.
     */
    instance() {
      return this.socket.web || null;
    }

    /**
     * Initializes the WebSocket connection using the configured URI.
     * This method is responsible for creating the WebSocket object and setting it up
     * for communication.
     * @returns {UWebSocket} Returns the instance of this UWebSocket for method chaining.
     */
    generate() {
      const uri = this.getUri();
      // Create a new WebSocket instance with the specified URI.
      this.socket.web = new WebSocket(uri);
      // Configure the binary type for the WebSocket; this is useful for terminals that may need to handle binary data.
      this.socket.web.binaryType = "arraybuffer";
      return this;
    }
  }

  /**
   * Represents the core terminal interface, integrating various components such as
   * WebSocket connectivity and user authentication to provide a comprehensive terminal experience.
   */
  class UTerminal {
    /**
     * Initializes a new instance of the UTerminal class, setting up the necessary components
     * for the terminal's operation including WebSocket connections and authentication modules.
     */
    constructor() {
      // Initialize the WebSocket connection component.
      this.mount = {};
      this.mount.websocket = new window.Terminal.UTerminal.UWebSocket(this);
      // Initialize the authentication module.
      this.mount.authentication = new window.Terminal.UTerminal.UAuthentication(
        this
      );
      // Placeholder for terminal-related elements.
      this.element = {};
      // Automatically load the terminal fit addon upon initialization.
      this.instance().loadAddon(this.getFitAddon());
    }

    /**
     * Instantiates or retrieves the current terminal instance, applying configuration as necessary.
     * @returns {Terminal} The terminal instance, configured for use.
     */
    instance() {
      // Check if the terminal instance already exists and return it; otherwise, create a new instance.
      if (this.mount.terminal instanceof Terminal) return this.mount.terminal;
      this.mount.terminal = new Terminal({
        cursorBlink: true, // Enable cursor blinking.
        convertEol: true, // Convert end-of-line characters to match the environment.
        theme: {
          background: '#222222' // Set background color
        }
      });
      return this.mount.terminal;
    }

    /**
     * Retrieves or instantiates the fit addon, used for automatically adjusting the terminal's size to fit its container.
     * @returns {FitAddon} The fit addon instance for the terminal.
     */
    getFitAddon() {
      // Check if the fit addon already exists and return it; otherwise, create a new instance.
      if (this.mount.fit instanceof FitAddon.FitAddon) return this.mount.fit;
      this.mount.fit = new FitAddon.FitAddon();
      return this.mount.fit;
    }

    /**
     * Retrieves the WebSocket connection manager associated with this terminal.
     * @returns {UWebSocket} The WebSocket connection manager.
     */
    getWebSocket() {
      return this.mount.websocket;
    }

    /**
     * Retrieves the authentication module associated with this terminal.
     * @returns {UAuthentication} The authentication module.
     */
    getAuthentication() {
      return this.mount.authentication;
    }

    /**
     * Creates or retrieves the container element for the terminal interface.
     * This element serves as the parent for the terminal's UI components.
     * @returns {HTMLElement} The container element for the terminal.
     */
    getContainer() {
      // Check if the container element already exists and return it; otherwise, create a new container element.
      if (this.element.hasOwnProperty("container"))
        return this.element.container;
      this.element.container = document.createElement("div");
      this.element.container.className = "terminal";
      return this.element.container;
    }
  }

  // Assigns the FitAddon class to the window.Terminal object, making the FitAddon functionality globally accessible.
  // This is particularly useful for terminal applications that need to dynamically adjust the terminal's size to fit its container.
  window.Terminal.FitAddon = FitAddon.FitAddon;

  // Attaches the UTerminal class to the window.Terminal namespace, making it accessible for creating terminal instances
  // within the global scope of the application. This serves as the entry point for terminal functionality.
  window.Terminal.UTerminal = UTerminal;

  // Attaches the UWebSocket class under the UTerminal namespace, enabling WebSocket communication functionality
  // to be easily accessible and instantiated within the context of the terminal application.
  window.Terminal.UTerminal.UWebSocket = UWebSocket;

  // Attaches the UAuthentication class under the UTerminal namespace, making authentication-related functionality
  // readily available for use in the terminal application, facilitating user login and authentication processes.
  window.Terminal.UTerminal.UAuthentication = UAuthentication;

  // Further nests the UElement class under the UAuthentication namespace, providing a structured way to access UI elements
  // related to authentication, such as form inputs and buttons, ensuring a modular approach to building the application's UI.
  window.Terminal.UTerminal.UAuthentication.UElement = UElement;
})(window);
