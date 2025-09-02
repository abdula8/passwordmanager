# Secure Password Manager

## Overview
The Secure Password Manager is a graphical user interface application designed to help users manage their passwords securely. It allows users to set a master password, add new passwords, and store them securely using encryption. The application also provides functionalities to copy passwords to the clipboard for easy access.

## Features
- Set and verify a master password.
- Add, view, and manage passwords for different services.
- Securely store passwords using encryption.
- Copy passwords to the clipboard for easy use.
- Generate strong random passwords based on user-defined criteria.

## File Structure
- `main.py`: Contains the main application logic and user interface.
- `passGen.py`: Provides functions to generate random passwords based on specified criteria.
- `setup_helper.py`: Contains helper functions for setting up necessary libraries and dependencies.
- `README.md`: Documentation for the project.

## Installation
To install the necessary dependencies, run the following command:

```
pip install -r requirements.txt
```

Make sure to have the following libraries installed:
- tkinter
- cryptography
- pyperclip
- keyring

## Usage
1. Run the application using the command:
   ```
   python main.py
   ```
2. On the login screen, enter your master password. If you are using the application for the first time, set a new master password.
3. Once logged in, you can add new passwords by entering the service name, username, and password.
4. Use the password generator to create strong passwords by integrating the functionality from `passGen.py`.
5. You can search for services and copy passwords to the clipboard as needed.

## Password Generation
The password generation functionality allows users to create strong passwords based on the following criteria:
- Length of the password
- Inclusion of uppercase letters
- Inclusion of lowercase letters
- Inclusion of digits
- Inclusion of special symbols

## Contributing
Contributions are welcome! Please feel free to submit a pull request or open an issue for any suggestions or improvements.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.