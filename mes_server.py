import socket
import threading
import json
import struct

class ChatServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen()
        self.clients = {}  # {client_id: socket}
        self.lock = threading.Lock()
        self.handshake_secret = "SECRET_HANDSHAKE_KEY"  # Секретный ключ для handshake
        print(f"Server started on {host}:{port}")

    def handle_client(self, client_socket, client_id):
        try:
            # Первым делом проверяем handshake
            handshake_data = self.recvall(client_socket, 4)
            if not handshake_data or len(handshake_data) != 4:
                client_socket.close()
                return
                
            handshake_len = struct.unpack('>I', handshake_data)[0]
            handshake_msg = self.recvall(client_socket, handshake_len)
            
            if not handshake_msg:
                client_socket.close()
                return
                
            try:
                handshake = json.loads(handshake_msg.decode('utf-8'))
                if handshake.get('secret') != self.handshake_secret:
                    client_socket.close()
                    return
            except:
                client_socket.close()
                return

            while True:
                # Сначала получаем длину сообщения
                raw_msglen = self.recvall(client_socket, 4)
                if not raw_msglen:
                    break
                msglen = struct.unpack('>I', raw_msglen)[0]
                
                # Затем получаем само сообщение
                message_data = self.recvall(client_socket, msglen)
                if not message_data:
                    break
                
                try:
                    message = json.loads(message_data.decode('utf-8'))
                    self.process_message(message, client_socket, client_id)
                except json.JSONDecodeError as e:
                    print(f"JSON decode error from {client_id}: {e}")
                    continue
        except Exception as e:
            print(f"Error with client {client_id}: {e}")
        finally:
            self.remove_client(client_id)

    def recvall(self, sock, n):
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    def process_message(self, message, client_socket, client_id):
        target_id = message.get('target_id')
        if not target_id or target_id not in self.clients:
            return

        try:
            # Упаковываем сообщение с указанием длины
            message_str = json.dumps(message)
            message_len = struct.pack('>I', len(message_str))
            full_message = message_len + message_str.encode('utf-8')
            
            with self.lock:
                if target_id in self.clients:
                    self.clients[target_id].sendall(full_message)
        except Exception as e:
            print(f"Error sending to {target_id}: {e}")
            self.remove_client(target_id)

    def remove_client(self, client_id):
        with self.lock:
            if client_id in self.clients:
                try:
                    self.clients[client_id].close()
                except:
                    pass
                del self.clients[client_id]
                print(f"Client {client_id} disconnected")

    def run(self):
        client_id_counter = 1
        while True:
            client_socket, addr = self.server.accept()
            client_id = f"client_{client_id_counter}"
            client_id_counter += 1
            
            with self.lock:
                self.clients[client_id] = client_socket
            print(f"New connection from {addr} as {client_id}")
            
            # Отправляем клиенту его ID
            try:
                welcome_msg = json.dumps({
                    'type': 'welcome', 
                    'client_id': client_id
                })
                welcome_len = struct.pack('>I', len(welcome_msg))
                client_socket.sendall(welcome_len + welcome_msg.encode('utf-8'))
            except:
                self.remove_client(client_id)
                continue
            
            thread = threading.Thread(
                target=self.handle_client, 
                args=(client_socket, client_id),
                daemon=True
            )
            thread.start()

if __name__ == "__main__":
    server = ChatServer()
    server.run()
