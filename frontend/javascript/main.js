// Initialize a new UTerminal instance and retrieve the authentication element.
const terminal = new window.Terminal.UTerminal(),
    element = terminal.getAuthentication().getElement();

// Register an event handler to handle terminal resize events.
terminal.instance().onResize(({ cols, rows }) => {
    // Retrieve the WebSocket instance from the terminal.
    const ws = terminal.getWebSocket().instance();

    // Check if the WebSocket connection is open before sending messages.
    if (WebSocket.OPEN !== ws.readyState) return;

    // Prepare a message to send through the WebSocket for terminal resizing.
    const message = JSON.stringify({
        action: 'resize',
        cols, rows
    });

    // Clear the terminal instance before applying the resize.
    terminal.instance().clear();

    // Send the resize message through the WebSocket.
    ws.send(message);
});


// Set a callback function to handle authentication actions.
element.setCallback(function () {
    // Define the WebSocket URI based on the current location.
    const uri = 'wss://' + window.location.host + '/ws',
        authentication = this.getAuthentication(),
        terminal = authentication.getTerminal(),
        // Set the URI for the WebSocket connection and retrieve the instance.
        ws = terminal.getWebSocket().setUri(uri).instance();

    // Create a new AttachAddon instance to attach the WebSocket to the terminal.
    const wsAddon = new AttachAddon.AttachAddon(ws);

    // Load the WebSocket addon into the terminal.
    terminal.instance().loadAddon(wsAddon);

    // Add an event listener for the WebSocket 'open' event.
    ws.addEventListener('open', () => {
        const instance = terminal.instance();
        // Write a connection established message in the terminal upon connection.
        instance.writeln('Connection established...');

        // Prepare credentials data to send through the WebSocket.
        const credentials = JSON.stringify({
            username: authentication.getUsername(),
            password: authentication.getPassword()
        });

        // Add event listeners for the WebSocket 'close' and 'error' events.
        ws.addEventListener('close', () => instance.writeln('Connection closed.'));
        ws.addEventListener('error', () => instance.writeln('Connection error.'));

        // Send the credentials data through the WebSocket.
        ws.send(credentials);

        // Remove the authentication element from the DOM.
        window.Terminal.UTerminal.UAuthentication.UElement.removeElementDOM(this.getContainer());

        // Append the terminal container to the body and open the terminal instance within it.
        const container = terminal.getContainer();
        document.body.appendChild(container);
        instance.open(container);

        // Fit the terminal within its container.
        terminal.getFitAddon().fit();

    });
});

// Append the authentication element's container to the body.
document.body.appendChild(element.getContainer());

// Add a window resize event listener to adjust the terminal's size.
window.addEventListener("resize", () => terminal.getFitAddon().fit(), false);
