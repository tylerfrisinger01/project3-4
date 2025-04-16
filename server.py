import socket

soc = socket.socket()

host_name = socket.gethostname()
s_ip = socket.gethostbyname(host_name)


port = 8080


print("Welcome to the chat room.")
soc.bind((host_name, port))
print("Binding successful")
print("This is your IP address: ", s_ip)


name = input("Enter your name: ")

soc.listen(1)

conn = soc.accept()
print("Received connection from: ", conn[0])
print("Connection Established. Connected from: ", conn[0])
client = (conn.recv(1024)).decode()
print(client + " has connected.")

conn.send(name.encode())

