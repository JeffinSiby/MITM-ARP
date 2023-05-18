import socket
import ssl

# Code inspired by https://pythontic.com/ssl/sslsocket/introduction and https://stackoverflow.com/questions/63980192/how-can-i-create-a-python-ssl-client-server-pair-where-only-the-server-authentic
# arguments are CA certificate file (cafile), the hostname (hostname), and the port number (port).
class SSLClient:
    def __init__(self, cacertfile_path, hostname, port):
        self.cacertfile_path = cacertfile_path
        self.hostname = hostname
        self.port = port
        
    def connect(self, server_ip, server_port, server_hostname):
        context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH,
            capath=self.cacertfile_path
            )
        context.load_verify_locations(cafile=self.cacertfile_path)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        server_address = (server_ip, server_port)
        sock.connect(server_address)

        ssl_sock = context.wrap_socket(
                                        sock,
                                        server_hostname= server_hostname,
                                        do_handshake_on_connect=True,
                                        server_side=False
                                        )
        sock.close()
        try:
            ssl_sock.sendall(b'Hello from client!')
            data = ssl_sock.recv(1024)
            # print(f'Received: {data.decode()}')

        finally:
            ssl_sock.shutdown(socket.SHUT_RDWR)
            ssl_sock.close()


if __name__ == '__main__':
    CA_CERT_PATH = "./client-certs/ca.crt"
    # IP = "127.0.0.1"
    IP = "10.9.0.5"
    PORT = 8081
    server = SSLClient(CA_CERT_PATH, IP, PORT)

    # SERVER_IP = "127.0.0.1"
    SERVER_IP = "10.9.0.6"
    SERVER_PORT = 8080
    SERVER_HOST_NAME = "www.technowizard.com"
    server.connect(SERVER_IP, SERVER_PORT, SERVER_HOST_NAME)

# Files moved into docker container using method suggested in https://stackoverflow.com/questions/22907231/how-to-copy-files-from-host-to-docker-container