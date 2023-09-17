import socket

# Create a TCP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Set the IP address and port
ip_address = '0.0.0.0'  # Replace with the IP address where the DNP3 packets are being sent
port = 20000

# Bind the socket to the IP address and port
sock.bind((ip_address, port))

# Listen for incoming connections
sock.listen(1)

print("Waiting for incoming connections...")

# Accept a client connection
client_sock, client_address = sock.accept()
print(f"Connected to: {client_address}")

# Receive and process DNP3 packets
while True:
    # Receive data from the client
    data = client_sock.recv(1024)  # Adjust the buffer size as per your requirements

    if not data:
        # No more data received, connection closed
        print("Connection closed by the client.")
        break

    # Process the received DNP3 packet
    # Add your code here to handle the DNP3 packet received in the 'data' variable

# Close the client socket
# client_sock.close()

# # Close the server socket
# sock.close()