import socket
import ssl
import threading
import logging
import time

def transfer_data(source_socket, destination_socket, log_file, initial_data=None):
    print("Start reading/writing sockets %s", log_file)
    if initial_data:
        destination_socket.sendall(initial_data)
        with open(log_file, 'ab') as f:
            f.write(initial_data)
    while getattr(threading.current_thread(), "do_run", True): 
        data = source_socket.recv(1024)
        if not data:
            print("End of data %s", log_file)
            break
        destination_socket.sendall(data)
        with open(log_file, 'ab') as f:
            f.write(data)
    print("Ended transfer %s", log_file)


def handle_connection(client_socket):
    # Upgrade the client socket to a secure socket
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="certs/server/teddy-cert.pem", keyfile="certs/server/teddy-key.pem")
    # context.load_verify_locations(cafile="certs/server/ca-root.pem")
    # context.verify_mode = ssl.CERT_REQUIRED
    secure_socket = context.wrap_socket(client_socket, server_side=True)

    # Receive data from the client
    data = secure_socket.recv(1024)
    binary = is_binary_data(data)

    client_cert_file = 'certs/client/client.pem'
    private_key_file = 'certs/client/private.pem'
    custom_ca_file = 'certs/client/ca.pem'

    url = "prod.de.tbs.toys"
    log_file = "data_stream.http.log"
    if binary:
        url = "rtnl.bxc.toys"
        log_file = "data_stream_up.rtnl.log"
        print("RTNL")
    else:
        print("HTTP")
    ip = socket.gethostbyname(url)

    forward_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    forward_socket.connect((ip, 443))

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(certfile=client_cert_file, keyfile=private_key_file)
    context.load_verify_locations(cafile=custom_ca_file)
    forward_socket_tls = context.wrap_socket(forward_socket, server_hostname=url)

    print("Initialized socket")

    # Create and start the thread for upstream (forward_socket_tls -> secure_socket)
    upstream_thread = threading.Thread(target=transfer_data, args=(forward_socket_tls, secure_socket, log_file))
    upstream_thread.start()

    # Create and start the thread for downstream (secure_socket -> forward_socket_tls)
    downstream_thread = threading.Thread(target=transfer_data, args=(secure_socket, forward_socket_tls, log_file, data))
    downstream_thread.start()

    # Wait for both threads to complete
    while downstream_thread.is_alive() and upstream_thread.is_alive():
        time.sleep(0.1)

    print("during")
    downstream_thread.do_run = False
    upstream_thread.do_run = False
    secure_socket.close()
    forward_socket_tls.close()

    while downstream_thread.is_alive() or upstream_thread.is_alive():
        time.sleep(0.1)

    print("Closed socket")
    secure_socket.close()

def is_binary_data(data):
    try:
        decoded_data = data.decode('utf-8')
        return not (decoded_data.startswith('GET') or decoded_data.startswith('POST'))
    except UnicodeDecodeError:
        return True


def run_tls_server():
    server_address = ('', 443)  # You can use any available port here
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(server_address)
    server_socket.listen(16)

    print('Waiting for incoming connections...')
    
    while True:
        client_socket, client_address = server_socket.accept()
        print("Connection from %s", client_address)
        threading.Thread(target=handle_connection, args=(client_socket,)).start()

run_tls_server()
