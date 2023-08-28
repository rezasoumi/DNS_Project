# Secure Command Prompt Messenger

This project is a secure messenger application designed to provide end-to-end encryption for communication between users in a command prompt environment. Users can send messages securely to each other, ensuring the confidentiality and integrity of their conversations. The application utilizes RSA and Diffie-Hellman key exchange to establish secure communication channels.

## Features

- **Help:** Display all available commands and their descriptions.
- **Online Users:** Show a list of all currently online users.
- **History Chat:** Display the chat history within a group or between users for each user.
- **Register:** Register a new user with the system.
- **Login:** Log in with a registered user.
- **Logout:** Log out from the current user session.
- **Regenerate RSA Key:** Generate new RSA private and public keys for the user.
- **Connect:** Connect two users and establish a Diffie-Hellman key between them for secure communication.
- **Send Offline:** Send messages to users when they are online, ensuring timely delivery.
- **End-to-End (E2E):** Send messages with end-to-end encryption using the previously established Diffie-Hellman key.
- **Create Group:** Create a new group for multiple users to communicate securely.
- **Add Group Member:** Add a new member to a group and establish a Diffie-Hellman key between all members.
- **Delete Group Member:** Remove a member from a group and regenerate the Diffie-Hellman key for the remaining members.
- **Send Group Message:** Send messages within a group with the established Diffie-Hellman key.
- **Add Group Admin:** Assign a new admin for the group.

## How to Run

1. Clone the repository to your local machine.
2. Open a terminal and navigate to the project directory.
3. Run the server by executing the command: `python server.py`
4. Open multiple terminals for each client.
5. In each client terminal, run the command with the desired client name: 
   - `python client.py reza`
   - `python client.py ali`
   - `python client.py pourya`

## Usage

- Upon starting the client, log in with an existing user or register a new user using the appropriate commands.
- Use `help` command to get information about all available commands and their usage.
- Use various commands to manage contacts, send messages, and interact with groups.

## Security Mechanisms

- The application employs RSA encryption for secure communication of sensitive data, such as private keys.
- Diffie-Hellman key exchange is used to establish secure communication channels between users, ensuring confidentiality and integrity of messages.
- End-to-end encryption is implemented using the established Diffie-Hellman keys, providing robust security for communication within and between groups.

## Contributing

Contributions to this project are welcome! If you have suggestions, bug reports, or improvements, please feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This project is for educational and demonstrational purposes only. It is not intended for production use, and the developers assume no liability for any misuse or unintended application of this software.

