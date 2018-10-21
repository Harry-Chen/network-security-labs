import socket

LISTEN = ('127.0.0.1', 8653)
TARGET_SERVER = ('8.8.8.8', 53) # good dns
TEST_SERVER = ('1.2.3.4', 53) # unreachable overseas endpoint
DGRAM_MAXSIZE = 65536

server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_sock.bind(LISTEN)

print('started!')

def is_polluted(query):
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    test_sock.connect(TEST_SERVER)
    test_sock.settimeout(0.1) # magic!
    test_sock.send(query)
    try:
        test_sock.recv(DGRAM_MAXSIZE)
        return True
    except socket.timeout as e:
        return False
    finally:
        test_sock.close()

def do_query(query):
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.connect(TARGET_SERVER)
    client_sock.settimeout(1) # magic!
    client_sock.send(query)
    answers = []
    try:
        for i in range(3 if is_polluted(query) else 1):
            data = client_sock.recv(DGRAM_MAXSIZE)
            answers.append(data)
    except socket.timeout as e:
        pass
    client_sock.close()
    return answers[-1] if answers else None

while True:
    data, addr = server_sock.recvfrom(DGRAM_MAXSIZE)
    if not data:
        print('something goes wrong')
        exit(1)
    answer = do_query(data)
    if answer:
        server_sock.sendto(answer, addr)

server_sock.close()

