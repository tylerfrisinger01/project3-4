import socket
import struct
import os
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def generate_keys():
  if not os.path.exists("client_private.pem"):
    key = RSA.generate(2048)
    with open("client_private.pem", "wb") as f:
      f.write(key.export_key())
    with open("client_public.pem", "wb") as f:
      f.write(key.publickey().export_key())

def recv_exact(sock, n):
  data = bytearray()
  while len(data) < n:
    packet = sock.recv(n - len(data))
    if not packet:
      return None
    data.extend(packet)
  return bytes(data)

def main():
  generate_keys()
  client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server_host = input("Enter server IP: ")
  client_socket.connect((server_host, 8080))
  name = input("Enter your name: ")

  encoded_name = name.encode('utf-8')
  client_socket.sendall(struct.pack('!I', len(encoded_name)))  # Length
  client_socket.sendall(encoded_name)  # Actual name

  # Send public key
  with open("client_public.pem", "rb") as f:
    pub_key = f.read()
    client_socket.sendall(struct.pack('!I', len(pub_key)) + pub_key)

  def receive():
    while True:
      try:
        enc_key_len_data = recv_exact(client_socket, 4)
        if not enc_key_len_data:
          break
        enc_key_len = struct.unpack('!I', enc_key_len_data)[0]
        
        # Receive encrypted key
        encrypted_key = recv_exact(client_socket, enc_key_len)
        if not encrypted_key:
          break

        iv = recv_exact(client_socket, 16)
        if not iv:
          break

        ciphertext_len_data = recv_exact(client_socket, 4)
        if not ciphertext_len_data:
          break
        ciphertext_len = struct.unpack('!I', ciphertext_len_data)[0]
        
        # Receive ciphertext
        ciphertext = recv_exact(client_socket, ciphertext_len)
        if not ciphertext:
          break

        # Decrypt
        private_key = RSA.import_key(open("client_private.pem", "rb").read())
        session_key = PKCS1_OAEP.new(private_key).decrypt(encrypted_key)
        plaintext = unpad(AES.new(session_key, AES.MODE_CBC, iv).decrypt(ciphertext), AES.block_size).decode()
        print(f"\n[Received] {plaintext}\nEnter message: ", end='')
      except:
        break
    client_socket.close()

  threading.Thread(target=receive, daemon=True).start()

  while True:
      message = input("Enter message: ")
      if message.lower() == 'exit':
        break

      # Encrypt message
      session_key = get_random_bytes(32)
      iv = get_random_bytes(16)
      cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
      ciphertext = cipher_aes.encrypt(pad(message.encode(), AES.block_size))
      server_pub_key = RSA.import_key(open("server_public.pem", "rb").read())
      encrypted_key = PKCS1_OAEP.new(server_pub_key).encrypt(session_key)
      signature = pkcs1_15.new(RSA.import_key(open("client_private.pem", "rb").read())).sign(SHA256.new(message.encode()))

      # Send data
      data = (
        struct.pack('!I', len(encrypted_key)) + encrypted_key +
        iv +
        struct.pack('!I', len(ciphertext)) + ciphertext +
        struct.pack('!I', len(signature)) + signature
      )
      client_socket.sendall(data)

  client_socket.close()

if __name__ == "__main__":
  main()