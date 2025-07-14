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
        self.handshake_secret = "SECRET_HANDSHAKE_KEY"
        self.client_id_counter = 1
        print(f"Server started on {host}:{port}")

    def handle_client(self, client_socket, client_id):
        try:
            while True:
                # Получаем длину сообщения
                raw_msglen = self.recvall(client_socket, 4)
                if not raw_msglen:
                    break
                msglen = struct.unpack('>I', raw_msglen)[0]
                
                # Получаем само сообщение
                message_data = self.recvall(client_socket, msglen)
                if not message_data:
                    break
                
                try:
                    message = json.loads(message_data.decode('utf-8'))
                    self.process_message(message, client_id)
                except json.JSONDecodeError as e:
                    print(f"JSON decode error from {client_id}: {e}")
        except Exception as e:
            print(f"Error with client {client_id}: {e}")
        finally:
            self.remove_client(client_id)

    def verify_handshake(self, client_socket):
        """Проверяет handshake и возвращает True если он верный"""
        try:
            handshake_data = self.recvall(client_socket, 4)
            if not handshake_data or len(handshake_data) != 4:
                return False
                
            handshake_len = struct.unpack('>I', handshake_data)[0]
            handshake_msg = self.recvall(client_socket, handshake_len)
            
            if not handshake_msg:
                return False
                
            try:
                handshake = json.loads(handshake_msg.decode('utf-8'))
                return handshake.get('secret') == self.handshake_secret
            except:
                return False
        except:
            return False

    def register_client(self, client_socket, addr):
        """Регистрирует клиента только после успешного handshake"""
        # Проверяем handshake
        if not self.verify_handshake(client_socket):
            client_socket.close()
            print(f"Handshake failed from {addr}")
            return None

        # Создаем client_id
        with self.lock:
            client_id = f"client_{self.client_id_counter}"
            self.client_id_counter += 1
            self.clients[client_id] = client_socket

        print(f"New authenticated connection from {addr} as {client_id}")

        # Отправляем приветственное сообщение
        try:
            welcome_msg = json.dumps({
                'type': 'welcome',
                'client_id': client_id
            })
            welcome_len = struct.pack('>I', len(welcome_msg))
            client_socket.sendall(welcome_len + welcome_msg.encode('utf-8'))
            return client_id
        except:
            self.remove_client(client_id)
            return None

    def recvall(self, sock, n):
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    def process_message(self, message, sender_id):
        target_id = message.get('target_id')
        if not target_id or target_id not in self.clients:
            return

        try:
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
        while True:
            client_socket, addr = self.server.accept()
            
            # Регистрируем клиента (с проверкой handshake)
            client_id = self.register_client(client_socket, addr)
            if not client_id:
                continue
            
            # Запускаем обработчик клиента
            thread = threading.Thread(
                target=self.handle_client,
                args=(client_socket, client_id),
                daemon=True
            )
            thread.start()

if __name__ == "__main__":
    server = ChatServer()
    server.run()
