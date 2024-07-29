import socket
import os
import shutil
from cryptography.fernet import Fernet
import hashlib
import base64
import re
import tqdm

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 5001
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"

def create_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def is_valid_ip(ip):
    regex = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.match(regex, ip) is not None

def show_welcome():
    print(r"""
     _               _    _____ _       
    | |    ___   ___| | _|  ___| |_   _ 
    | |   / _ \ / __| |/ / |_  | | | | |
    | |__| (_) | (__|   <|  _| | | |_| |
    |_____\___/ \___|_|\_\_|   |_|\__, |
                                  |___/ 
    """)

def show_help():
    print(r"""
    ************************************************
    *                HELP PAGE                     *
    ************************************************
    * This application allows you to securely      *
    * send and receive files.                      *
    *                                              *
    * Developed by: dkhan25 (GitHub)               *
    * License: MIT License                         *
    *                                              *
    * Options:                                     *
    * 1. Receive File: Run the server to receive   *
    *    encrypted files.                          *
    *                                              *
    * 2. Send File: Run the client to send         *
    *    encrypted files.                          *
    ************************************************
    """)

def check_disk_space(path, required_space):
    total, used, free = shutil.disk_usage(path)
    return free >= required_space

def start_server():
    session_password = input("Set the session password: ")
    key = create_key(session_password)
    cipher = Fernet(key)

    print("[INFO] Starting the server...")
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((SERVER_HOST, SERVER_PORT))
    s.listen(5)
    print(f"[INFO] Listening as {SERVER_HOST}:{SERVER_PORT}")

    try:
        while True:
            client_socket, address = s.accept()
            print(f"[INFO] {address} is connected.")

            received_password = client_socket.recv(BUFFER_SIZE).decode().strip()
            print(f"[INFO] Password received")

            if received_password != session_password:
                print("[WARNING] Incorrect session password.")
                client_socket.close()
                continue

            client_socket.send(b"OK")

            received = client_socket.recv(BUFFER_SIZE).decode()
            parts = received.split(SEPARATOR)
            if len(parts) != 2:
                print("[ERROR] Invalid file info received.")
                client_socket.close()
                continue

            filename, filesize_str = parts
            filename = os.path.basename(filename)
            try:
                filesize = int(filesize_str)
                print(f"[INFO] File info received")
            except ValueError:
                print("[ERROR] Error converting filesize to integer")
                client_socket.close()
                continue

            if not check_disk_space('.', filesize):
                print("[ERROR] Not enough disk space to receive the file.")
                client_socket.close()
                continue

            try:
                encrypted_data = b""
                with open(filename + ".enc", "wb") as f:
                    progress = tqdm.tqdm(range(filesize), f"Receiving file", unit="B", unit_scale=True, unit_divisor=1024)
                    while True:
                        bytes_read = client_socket.recv(BUFFER_SIZE)
                        if not bytes_read:
                            break
                        f.write(bytes_read)
                        encrypted_data += bytes_read
                        progress.update(len(bytes_read))
                    progress.close()

                decrypted_data = cipher.decrypt(encrypted_data)
                with open(filename, "wb") as f:
                    f.write(decrypted_data)

                print(f"[INFO] File received and decrypted successfully.")

                os.remove(filename + ".enc")
                client_socket.close()
            except Exception as e:
                print(f"[ERROR] An error occurred: {e}")
                if os.path.exists(filename + ".enc"):
                    os.remove(filename + ".enc")
                client_socket.close()
                continue
    except KeyboardInterrupt:
        print("\n[INFO] Server is shutting down gracefully.")
        s.close()

def start_client():
    try:
        server_host = input("Enter the server IP address: ")
        while not is_valid_ip(server_host):
            print("[WARNING] Invalid IP address. Please enter a valid IP address.")
            server_host = input("Enter the server IP address: ")

        session_password = input("Enter the session password: ")
        key = create_key(session_password)
        cipher = Fernet(key)

        while True:
            filename = input("Enter the file path to send: ")
            filesize = os.path.getsize(filename)

            with open(filename, "rb") as f:
                file_data = f.read()
            encrypted_data = cipher.encrypt(file_data)
            print(f"[INFO] File encrypted")

            s = socket.socket()
            s.connect((server_host, SERVER_PORT))

            s.send(session_password.encode())
            print("[INFO] Session password sent")

            confirmation = s.recv(BUFFER_SIZE).decode().strip()
            if confirmation != "OK":
                print("[WARNING] Password verification failed")
                s.close()
                return
            print("[INFO] Password verified")

            file_info = f"{filename}{SEPARATOR}{len(encrypted_data)}"
            print(f"[INFO] Sending file info")
            s.send(file_info.encode())
            print("[INFO] File info sent")

            progress = tqdm.tqdm(range(len(encrypted_data)), f"Sending file", unit="B", unit_scale=True, unit_divisor=1024)
            for i in range(0, len(encrypted_data), BUFFER_SIZE):
                s.sendall(encrypted_data[i:i+BUFFER_SIZE])
                progress.update(BUFFER_SIZE)
            progress.close()
            print("[INFO] Encrypted file data sent")

            s.close()
            print(f"[INFO] File sent and encrypted successfully.")

            another = input("Would you like to send another file? (yes/no): ").strip().lower()
            if another != 'yes':
                break

    except KeyboardInterrupt:
        print("\n[INFO] Client operation interrupted. Exiting gracefully.")

if __name__ == "__main__":
    show_welcome()
    while True:
        try:
            print("\nOptions:\n1. Send File\n2. Receive File\n3. Help\n4. Exit")
            choice = input("Choose an option: ").strip()
            if choice == '1':
                start_client()
            elif choice == '2':
                start_server()
            elif choice == '3':
                show_help()
            elif choice == '4':
                print("Goodbye!")
                break
            else:
                print("[WARNING] Invalid choice, please select a valid option.")
        except KeyboardInterrupt:
            print("\n[INFO] Application interrupted. Exiting gracefully.")
            break
