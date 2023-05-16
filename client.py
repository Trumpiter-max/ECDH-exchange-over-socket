import socket
import threading
import ast
from Diffie_Hellman import *

def convert_tuple(tup):
    string_elements = [str(element) for element in tup]
    result = "(" + ", ".join(string_elements) + ")"
    return result

def convert_string(string):
    # Removing the parentheses from the string
    result = ast.literal_eval(string)
    return result

def receive_message(sock, key_exchange):
    while True:
        try:
            data = sock.recv(1024).decode('utf-8')
            message = convert_string(data)
            message = decrypt(message, str(key_exchange[0]))
            print("\nClient: " + str(message))
        except OSError:
            break

def receive_key(sock):
    data = sock.recv(1024).decode('utf-8')
    global server_key
    server_key = int(data)

def send_message(sock, key_exchange):
    while True:
        message = input("Message: ")
        print("Client :", message)
        encrypted_message = encrypt(message, str(key_exchange[0]))
        encrypted_message = convert_tuple(encrypted_message)
        sock.sendall(encrypted_message.encode('utf-8'))

def send_key(key, sock):
    sock.sendall(str(key).encode('utf-8'))

def main():
    # Prepare connection
    host = 'localhost'
    port = 12345

    # Prepare for secure message
    ec = EllipticCurve(0,7,115792089237316195423570985008687907853269984665640564039457584007908834671663  )
    numberPoints = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    point = (
                int("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",16),
                int("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",16)
            )
    
    client_private_key = rand.getrandbits(256)%numberPoints
    client_public_key = ec.multiply(client_private_key, point)

    # Create a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to server's machine
    sock.connect((host, port))

    # Send and receive key
    send_key(client_private_key, sock)
    receive_key(sock)

    # Create key exchange
    key_exchange = ec.multiply(client_private_key*server_key, point)

    # Start a thread to receive messages from server
    receive_thread = threading.Thread(target=receive_message, args=(sock, key_exchange, ))
    receive_thread.start()

    # Send messages to server
    send_message(sock, key_exchange)

    # Close the socket
    sock.close()

if __name__ == '__main__':
    main()
