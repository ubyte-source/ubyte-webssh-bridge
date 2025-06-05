# Ubyte WebSSH Bridge

Ubyte WebSSH Bridge is an innovative WebSocket-based SSH client that enables secure and interactive SSH sessions directly from your web browser. This project leverages modern web technologies to provide an easy-to-use interface for managing SSH connections, supporting features like terminal resizing and user authentication.

## Features

- **WebSocket-based SSH Connection**: Secure and real-time communication between the client and SSH server.
- **Terminal Resizing**: Dynamically adjust the size of the terminal according to the browser window.
- **User Authentication**: Supports username and password authentication for SSH sessions.
- **Debug Mode**: Includes a debug mode for logging detailed information during development or troubleshooting.

## Installation

To install Ubyte WebSSH Bridge, ensure you have Go installed on your system. Follow these steps:

```bash
git clone https://github.com/ubyte-source/ubyte-webssh-bridge.git
cd ubyte-webssh-bridge
go build .
```

## Usage

Start the server with the default settings using:

```bash
./ubyte-webssh-bridge
```

This will listen on `:8080` by default.

### Configuration Options

- **`-address`**: Use to specify a custom address and port (e.g., `-address=":8089"` for all interfaces on port 8089).
- **`-debug`**: Enable debug mode for detailed logs (`-debug=true`).

## Running with Docker

`ubyte-webssh-bridge` is available as a Docker image and can be easily set up and run in a Docker container. This section guides you through pulling the Docker image, running a container with the necessary environment variables, and customizing the configuration as needed.

### Pulling the Docker Image

First, pull the `ubyte-webssh-bridge` image from Docker Hub:

```bash
docker pull ubyte/ubyte-webssh-bridge:latest
```

### Starting the Container with Environment Variables

To run `ubyte-webssh-bridge` properly, certain environment variables must be set to configure SSL certificates and the SSH connection. Use the `-e` flag with `docker run` to specify these variables:

```bash
docker run -dit -p 8443:8443 \
  -e COUNTRY="IT" \
  -e STATE="Vicenza" \
  -e CITY="Schio" \
  -e ORGANIZATION="IBS s.r.l." \
  -e ORGANIZATIONAL_UNIT="Network" \
  -e COMMON_NAME="supia.it" \
  -e HOST="10.12.0.236" \
  -e PORT="22" \
  ubyte/ubyte-webssh-bridge
```

This command starts the `ubyte-webssh-bridge` container in detached mode and sets up the environment with the required information for SSL and SSH configuration. The `-p` flag maps port 8443 of the container to port 8443 on the host, making the web interface accessible via `https://localhost:8443`.

### Adjustments and Customization

- **Port Mapping**: If you prefer to use a different port on the host, adjust the `-p` option accordingly (e.g., `-p 9443:8443` to use port 9443 on the host).

By following these instructions, you can deploy `ubyte-webssh-bridge` in a Docker container with all necessary configurations for SSL and SSH connections tailored to your environment.

## Contributing

We warmly welcome contributions from the community! If you're looking to improve Ubyte WebSSH Bridge, here's how you can help:

1. **Fork the Repository**: Start by forking the `ubyte-webssh-bridge` repository to your own GitHub account. This creates your own copy of the project where you can make changes.

2. **Create a New Branch**: In your forked repository, create a new branch for your contribution. Name it after the feature you're adding or the issue you're fixing, e.g., `feature/new-auth-method` or `fix/connection-timeout`.

3. **Commit Your Changes**: Make your changes in the new branch and commit them. Write clear, concise commit messages that explain your changes. This helps reviewers understand your intentions and the impact of your work.

4. **Push Your Changes and Open a Pull Request**: Push your branch to your GitHub repository and then open a pull request against the `ubyte-webssh-bridge` main branch. In your pull request, describe what you've changed and why. If your changes address an existing issue, include a reference to it in the description.

### Best Practices

- **Adhere to Coding Standards**: Ensure your code follows the project's coding standards. This maintains the codebase's readability and consistency.

- **Include Tests**: If your contribution adds new features or fixes bugs, include tests that cover these changes. Tests help ensure your changes work as expected and prevent future regressions.

- **Documentation**: Update the README or any relevant documentation if your changes alter how users interact with the project or if you're introducing new features.

By following these guidelines, you'll contribute to making Ubyte WebSSH Bridge even better. We look forward to your contributions!

## Support

If you encounter any issues or have questions, please file an issue on the GitHub issue tracker.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
