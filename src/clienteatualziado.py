import socket
import os
from ftp1 import get_file, put_file,dir_file

# The functions from the TFTP module you provided
# (pack_rrq, pack_wrq, get_file, put_file, etc.)

def show_help():
    print("Available commands:")
    print("  get <filename> - Download a file from the server")
    print("  put <filename> - Upload a file to the server")
    print("  help - Show this help message")
    print("  exit - Exit the TFTP client")

def main():
    server_address = input("Enter TFTP server address: ")
    server_port = int(input("Enter TFTP server port: "))
    server_addr = (server_address, server_port)

    print(f"Connected to TFTP server at {server_addr}")

    try:
        while True:
            user_input = input("TFTP> ").split()

            if not user_input:
                continue

            command = user_input[0].lower()

            if command == 'get':
                if len(user_input) < 2:
                    print("Usage: get <filename>")
                    continue
                filename = user_input[1]
                try:
                    get_file(server_addr, filename)
                    print(f"File '{filename}' downloaded successfully.")
                except Exception as e:
                    print(f"Error downloading file: {e}")

            elif command == 'put':
                if len(user_input) < 3:
                    print("Usage: put  <filename> <remote_file>")
                    continue
                local_filename = user_input[1]
                remote_filename  = user_input[2]
                try:
                    put_file(server_addr, local_filename,remote_filename)
                    print(f"File '{filename}' downloaded successfully.")
                except Exception as e:
                    print(f"Error uploading the file: {e}")
            elif command == 'help':
                    show_help() 
            elif command == 'dir':
                if len(user_input) < 1:
                    print("Usage: dir")
                else:
                    dir_file()
                print("Exiting TFTP client.")
                break

            else:
                print("Invalid command. Type 'help' for a list of commands.")

    except KeyboardInterrupt:
        print("\nTFTP client terminated by user.")

if __name__ == '__main__':
    main()