import socket
import threading
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

clients = {}
server_private_key = RSA.import_key(open("server_private.pem", "rb").read())

def recv_exact(sock, n):
  data = bytearray()
  while len(data) < n:
    packet = sock.recv(n - len(data))
    if not packet:
      return None
    data.extend(packet)
  return bytes(data)

def handle_client(conn, addr):
  name = "Unknown" 
  try:
    name_len_data = recv_exact(conn, 4)
    if not name_len_data:
      print(f"Client at {addr} disconnected prematurely.")
      return
    name_len = struct.unpack('!I', name_len_data)[0]
    
    # Receive name
    name_data = recv_exact(conn, name_len)
    if not name_data:
      print(f"Client at {addr} disconnected during name transfer.")
      return
    
    try:
      name = name_data.decode('utf-8')
    except UnicodeDecodeError:
      name = "InvalidName"

    # Receive public key length (4 bytes)
    key_len_data = recv_exact(conn, 4)
    if not key_len_data:
      print(f"{name} disconnected during key exchange.")
      return
    key_len = struct.unpack('!I', key_len_data)[0]
    
    # Receive public key
    pub_key_data = recv_exact(conn, key_len)
    if not pub_key_data:
      print(f"{name} disconnected during key transfer.")
      return
    client_pub_key = RSA.import_key(pub_key_data)

    clients[conn] = {'name': name, 'pub_key': client_pub_key}
    print(f"{name} connected from {addr}")

    while True:
      # Receive encrypted session key length (4 bytes)
      enc_key_len_data = recv_exact(conn, 4)
      if not enc_key_len_data:
        break
      enc_key_len = struct.unpack('!I', enc_key_len_data)[0]
      
      # Receive encrypted session key
      enc_session_key = recv_exact(conn, enc_key_len)
      if not enc_session_key:
        break

      iv = recv_exact(conn, 16)
      if not iv:
        break

      # Receive ciphertext length (4 bytes)
      ciphertext_len_data = recv_exact(conn, 4)
      if not ciphertext_len_data:
        break
      ciphertext_len = struct.unpack('!I', ciphertext_len_data)[0]
      
      # Receive ciphertext
      ciphertext = recv_exact(conn, ciphertext_len)
      if not ciphertext:
        break

      sig_len_data = recv_exact(conn, 4)
      if not sig_len_data:
        break
      sig_len = struct.unpack('!I', sig_len_data)[0]
      
      # Receive signature
      signature = recv_exact(conn, sig_len)
      if not signature:
        break

      # Decrypt and verify
      cipher_rsa = PKCS1_OAEP.new(server_private_key)
      session_key = cipher_rsa.decrypt(enc_session_key)
      cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
      message = unpad(cipher_aes.decrypt(ciphertext), AES.block_size).decode()

      h = SHA256.new(message.encode())
      try:
        pkcs1_15.new(client_pub_key).verify(h, signature)
        print(f"Valid message from {name}: {message}")
        broadcast(message, name, conn)
      except:
        print(f"Invalid signature from {name}")

  except Exception as e:
    print(f"Error with {name}: {e}")
  finally:
    if conn in clients:
      del clients[conn]
    conn.close()

def broadcast(message, sender_name, sender_conn):
  for conn in list(clients.keys()):
    if conn != sender_conn:
      try:
        client_pub_key = clients[conn]['pub_key']
        session_key = get_random_bytes(32)
        iv = get_random_bytes(16)
        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        ciphertext = cipher_aes.encrypt(pad(message.encode(), AES.block_size))
        encrypted_key = PKCS1_OAEP.new(client_pub_key).encrypt(session_key)

        data = (
          struct.pack('!I', len(encrypted_key)) + encrypted_key +
          iv +
          struct.pack('!I', len(ciphertext)) + ciphertext
        )
        conn.sendall(data)
      except:
        conn.close()
        del clients[conn]

if __name__ == "__main__":
  server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  host = socket.gethostname()
  port = 8080
  server_socket.bind((host, port))
  server_socket.listen()
  print(f"Server started at {socket.gethostbyname(host)}:{port}")

  while True:
    conn, addr = server_socket.accept()
    threading.Thread(target=handle_client, args=(conn, addr)).start()