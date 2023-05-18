import socket
import ssl

# Code inspired by https://pythontic.com/ssl/sslsocket/introduction and https://stackoverflow.com/questions/63980192/how-can-i-create-a-python-ssl-client-server-pair-where-only-the-server-authentic
# Arguements are certificate file (certfile), the private key file (keyfile), and the port number (port).
class SSLServer:
    def __init__(self, certfile_path, keyfile_path, cacertfile_path, ip, port):
        self.certfile = certfile_path
        self.keyfile = keyfile_path
        self.cacertfile_path = cacertfile_path
        self.port = port
        self.ip = ip
        
    def start(self):
        context = ssl.create_default_context(
            ssl.Purpose.CLIENT_AUTH,
            capath=self.cacertfile_path
            )
        context.load_cert_chain(
            certfile=self.certfile,
            keyfile=self.keyfile
            )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        server_address = (self.ip, self.port)
        sock.bind(server_address)

        sock.listen(1)

        while True:
            print('Waiting for a connection...')
            ssl_connection = None
            try:
                connection, client_address = sock.accept()
                ssl_connection = context.wrap_socket(
                    connection,
                    server_side=True,
                    do_handshake_on_connect=True
                    )
                connection.close()

                print(f'Connection from {client_address}')

                data = ssl_connection.recv(1024)
                print(f'Received: {data.decode()}')
                # ssl_connection.sendall(b'Message from erver!')
            except KeyboardInterrupt:
                if ssl_connection is not None:
                    ssl_connection.shutdown(socket.SHUT_RDWR)
                    ssl_connection.close()
                print("Stopping...")
                return

if __name__ == '__main__':
    CERTFILE_PATH = "./server-certs/server.crt"
    KEYFILE_PATH = "./server-certs/server.key"
    CA_CERT_PATH = "./server-certs/ca.crt" # same as ./client-certs/ca.crt
    # IP = "127.0.0.1"
    IP = "10.9.0.6"

    PORT = 8080
    server = SSLServer(CERTFILE_PATH, KEYFILE_PATH, CA_CERT_PATH, IP, PORT)
    server.start()

# Files moved into docker container using method suggested in https://stackoverflow.com/questions/22907231/how-to-copy-files-from-host-to-docker-container