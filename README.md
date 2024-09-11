# LockFly

LockFly is a simple secure file transfer application designed to facilitate the secure and encrypted transfer of files between devices. Leveraging Python's `cryptography` library, LockFly ensures data remains confidential and protected during transit.

## Features

- **Secure File Transfer**: Utilizes symmetric encryption (Fernet) from the `cryptography` library for data protection.
- **User-Friendly Interface**: Command-line interface with interactive prompts and progress bars for user confirmation.
- **Cross-Platform Compatibility**: Designed to run on both Unix-based systems and Windows.
- **Easy Setup**: Automated setup scripts to simplify the installation and execution process.
- **Disk Space Check**: Ensures there is enough disk space before starting the file transfer to avoid any crashes.

## Prerequisites

- Python 3.x

## Setup and Usage

1. **Clone the repository:**
    ```sh
    git clone https://github.com/CloudyKhan/lockfly.git
    cd lockfly
    ```

2. **Install dependencies:**

    You can install the dependencies manually using `pip`:

    ```sh
    pip install -r requirements.txt
    ```

    Or, you can use the provided setup script:

    ### Unix-based Systems
    ```sh
    chmod +x setup.sh
    ./setup.sh
    ```

    ### Windows
    ```bat
    setup.bat
    ```

3. **Run the Application**
    ```sh
    python lockfly.py
    ```
    
5. **Follow the interactive prompts to send or receive files.**

## Encryption Details

LockFly employs symmetric encryption using the Fernet module from the `cryptography` library. Fernet uses AES in CBC mode with a 128-bit key for encryption and HMAC for authentication. This ensures that files are encrypted with a key derived from a password provided by the user, ensuring that only users with the correct password can decrypt and access the transferred files.



