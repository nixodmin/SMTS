import socket
import json
import threading
import random
import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from Crypto.Random import get_random_bytes
import struct

class ChatClient:
    def __init__(self, server_host='YOUR_SERVER_IP', server_port=5555):
        self.server_host = server_host
        self.server_port = server_port
        self.client_id = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connections = {}  # {target_id: {'status': 'pending'|'established', 'key': bytes, 'key_hash': str}}
        self.dh_private_keys = {}
        self.lock = threading.Lock()
        self.handshake_secret = "SECRET_HANDSHAKE_KEY"  # Должен совпадать с серверным
        
        # Параметры Диффи-Хеллмана (RFC 3526, 2048 бит)
        self.dh_prime = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                          "29024E088A67CC74020BBEA63B139B22514A08798E3404D"
                          "DEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C"
                          "245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F40"
                          "6B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651EC"
                          "E45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
                          "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529"
                          "077096966D670C354E4ABC9804F1746C08CA18217C32905"
                          "E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C"
                          "55DF06F4C52C9DE2BCBF6955817183995497CEA956AE51"
                          "5D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
        self.dh_base = 2

    def connect(self):
        self.socket.connect((self.server_host, self.server_port))

        # Первым делом отправляем handshake
        handshake_msg = json.dumps({'secret': self.handshake_secret})
        handshake_len = struct.pack('>I', len(handshake_msg))
        self.socket.sendall(handshake_len + handshake_msg.encode('utf-8'))

        # Только после этого получаем welcome
        welcome_data = self.receive_json()
        if not welcome_data or 'client_id' not in welcome_data:
            self.socket.close()
            raise ConnectionError("Handshake failed")

        self.client_id = welcome_data['client_id']
        print(f"\nConnected as {self.client_id}")
        print("Type /help for commands\n")
        
        threading.Thread(target=self.receive_messages, daemon=True).start()
        self.user_interface()

    def send_json(self, message):
        try:
            message_str = json.dumps(message)
            message_len = struct.pack('>I', len(message_str))
            self.socket.sendall(message_len + message_str.encode('utf-8'))
            return True
        except Exception as e:
            print(f"\n[!] Send error: {str(e)}")
            return False

    def receive_json(self):
        try:
            raw_msglen = self.recvall(4)
            if not raw_msglen:
                return None
            msglen = struct.unpack('>I', raw_msglen)[0]
            
            message_data = self.recvall(msglen)
            if not message_data:
                return None
            
            return json.loads(message_data.decode('utf-8'))
        except Exception as e:
            print(f"\n[!] Receive error: {str(e)}")
            return None

    def recvall(self, n):
        data = bytearray()
        while len(data) < n:
            packet = self.socket.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    def derive_aes_key(self, shared_secret, peer_id, initiator_id):
        """Генерация AES ключа с учетом порядка клиентов"""
        id1, id2 = sorted([self.client_id, peer_id])
        key_material = (
            shared_secret.to_bytes(256, 'big') +
            id1.encode() + 
            id2.encode() +
            initiator_id.encode()
        )
        return hashlib.sha256(key_material).digest()

    def start_dh_exchange(self, target_id):
        if target_id == self.client_id:
            print("\n[!] Cannot connect to yourself")
            return

        with self.lock:
            if target_id in self.connections:
                print("\n[!] Connection already exists")
                return
            
            self.connections[target_id] = {'status': 'pending'}
        
        private_key = random.getrandbits(2048) % self.dh_prime
        public_key = pow(self.dh_base, private_key, self.dh_prime)
        
        with self.lock:
            self.dh_private_keys[target_id] = private_key
        
        print(f"\n[DH] Initiating key exchange with {target_id}")
        
        self.send_json({
            'type': 'dh_init',
            'from': self.client_id,
            'target_id': target_id,
            'public_key': str(public_key),
            'prime': str(self.dh_prime),
            'base': str(self.dh_base)
        })

    def complete_dh_exchange(self, target_id, their_public_key_str, is_initiator):
        try:
            their_public_key = int(their_public_key_str)
            with self.lock:
                private_key = self.dh_private_keys.get(target_id)
                if private_key is None:
                    print("\n[!] Missing private key for DH exchange")
                    return
            
            shared_secret = pow(their_public_key, private_key, self.dh_prime)
            
            initiator_id = self.client_id if is_initiator else target_id
            aes_key = self.derive_aes_key(shared_secret, target_id, initiator_id)
            key_hash = hashlib.sha256(aes_key).hexdigest()[:8]
            
            with self.lock:
                self.connections[target_id] = {
                    'status': 'established',
                    'key': aes_key,
                    'key_hash': key_hash
                }
            
            print(f"\n[DH] Key exchange with {target_id} completed!")
            print(f"[DH] Key fingerprint: {key_hash}")
            print("> ", end="", flush=True)
        except Exception as e:
            print(f"\n[!] Key exchange error: {str(e)}")

    def encrypt_message(self, message, target_id):
        with self.lock:
            conn = self.connections.get(target_id)
            if not conn or conn['status'] != 'established':
                print(f"\n[!] No established connection with {target_id}")
                return None
            aes_key = conn['key']
        
        try:
            message_bytes = message.encode('utf-8')
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(message_bytes, AES.block_size))
            return base64.b64encode(iv + ct_bytes).decode('utf-8')
        except Exception as e:
            print(f"\n[!] Encryption error: {str(e)}")
            return None

    def decrypt_message(self, ciphertext, sender_id):
        with self.lock:
            conn = self.connections.get(sender_id)
            if not conn or conn['status'] != 'established':
                return None
            
            aes_key = conn['key']
        
        try:
            data = base64.b64decode(ciphertext)
            if len(data) < 16 + AES.block_size:
                raise ValueError("Invalid ciphertext length")
                
            iv, ct = data[:16], data[16:]
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt.decode('utf-8')
        except ValueError as e:
            print(f"\n[!] Decryption error (key: {conn.get('key_hash', 'unknown')}): {str(e)}")
            return None
        except Exception as e:
            print(f"\n[!] Decryption error: {str(e)}")
            return None

    def encrypt_file_data(self, file_data, target_id):
        with self.lock:
            conn = self.connections.get(target_id)
            if not conn or conn['status'] != 'established':
                print(f"\n[!] No established connection with {target_id}")
                return None
            aes_key = conn['key']
        
        try:
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(file_data, AES.block_size))
            return base64.b64encode(iv + ct_bytes).decode('utf-8')
        except Exception as e:
            print(f"\n[!] File encryption error: {str(e)}")
            return None

    def decrypt_file_data(self, encrypted_data, sender_id):
        with self.lock:
            conn = self.connections.get(sender_id)
            if not conn or conn['status'] != 'established':
                print(f"\n[!] No established connection with {sender_id}")
                return None
            
            aes_key = conn['key']
        
        try:
            data = base64.b64decode(encrypted_data)
            if len(data) < AES.block_size:
                raise ValueError("Data too short to contain IV")
                
            iv = data[:AES.block_size]
            ct = data[AES.block_size:]
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt
        except ValueError as e:
            print(f"\n[!] File decryption error (key: {conn.get('key_hash', 'unknown')}): {str(e)}")
            return None
        except Exception as e:
            print(f"\n[!] File decryption error: {str(e)}")
            return None

    def receive_messages(self):
        while True:
            try:
                message = self.receive_json()
                if not message:
                    break

                if message.get('type') == 'dh_init':
                    print(f"\n[DH] Received key exchange request from {message['from']}")
                    
                    try:
                        prime = int(message['prime'])
                        base = int(message['base'])
                        their_public_key = int(message['public_key'])
                    except:
                        print("\n[!] Invalid DH parameters")
                        continue
                    
                    private_key = random.getrandbits(2048) % prime
                    public_key = pow(base, private_key, prime)
                    
                    with self.lock:
                        self.dh_private_keys[message['from']] = private_key
                    
                    self.send_json({
                        'type': 'dh_response',
                        'from': self.client_id,
                        'target_id': message['from'],
                        'public_key': str(public_key)
                    })
                    
                    try:
                        shared_secret = pow(their_public_key, private_key, prime)
                        aes_key = self.derive_aes_key(shared_secret, message['from'], message['from'])
                        key_hash = hashlib.sha256(aes_key).hexdigest()[:8]
                        
                        with self.lock:
                            self.connections[message['from']] = {
                                'status': 'established',
                                'key': aes_key,
                                'key_hash': key_hash
                            }
                        
                        print(f"[DH] Key exchange with {message['from']} completed")
                        print(f"[DH] Key fingerprint: {key_hash}")
                        print("> ", end="", flush=True)
                    except Exception as e:
                        print(f"\n[!] Key computation error: {str(e)}")

                elif message.get('type') == 'dh_response':
                    print(f"\n[DH] Received response from {message['from']}")
                    self.complete_dh_exchange(message['from'], message['public_key'], is_initiator=True)

                elif message.get('type') == 'message':
                    decrypted = self.decrypt_message(message['data'], message['from'])
                    if decrypted:
                        print(f"\n[Private from {message['from']}]: {decrypted}")
                    print("> ", end="", flush=True)

                elif message.get('type') == 'file':
                    file_data = self.decrypt_file_data(message['data'], message['from'])
                    if file_data:
                        file_name = message['file_name']
                        if os.path.exists(file_name):
                            base, ext = os.path.splitext(file_name)
                            counter = 1
                            while os.path.exists(f"{base}_{counter}{ext}"):
                                counter += 1
                            file_name = f"{base}_{counter}{ext}"
                        
                        with open(file_name, 'wb') as f:
                            f.write(file_data)
                        
                        print(f"\n[File from {message['from']}] Saved as: {file_name} (size: {len(file_data)} bytes)")
                    print("> ", end="", flush=True)

                elif message.get('type') == 'broadcast_msg':
                    decrypted = self.decrypt_message(message['data'], message['from'])
                    if decrypted:
                        print(f"\n[Broadcast from {message['from']}]: {decrypted}")
                    print("> ", end="", flush=True)

            except Exception as e:
                print(f"\n[!] Receive error: {str(e)}")
                break

    def user_interface(self):
        while True:
            try:
                command = input("> ").strip()
                
                if command.startswith("/connect "):
                    target_id = command.split()[1]
                    self.start_dh_exchange(target_id)
                
                elif command.startswith("/msg "):
                    parts = command.split()
                    if len(parts) < 3:
                        print("\nUsage: /msg [client_id] [message]")
                        continue
                    
                    target_id, message = parts[1], ' '.join(parts[2:])
                    encrypted = self.encrypt_message(message, target_id)
                    
                    if not encrypted:
                        print("> ", end="", flush=True)
                        continue
                    
                    self.send_json({
                        'type': 'message',
                        'from': self.client_id,
                        'target_id': target_id,
                        'data': encrypted
                    })
                
                elif command.startswith("/send "):
                    parts = command.split()
                    if len(parts) != 3:
                        print("\nUsage: /send [client_id] [filename]")
                        continue
                    
                    target_id, filename = parts[1], parts[2]
                    
                    if not os.path.exists(filename):
                        print(f"\n[!] File not found: {filename}")
                        print("> ", end="", flush=True)
                        continue
                    
                    try:
                        with open(filename, 'rb') as f:
                            file_data = f.read()
                        
                        if len(file_data) > 10 * 1024 * 1024:
                            print("\n[!] File too large (max 10MB)")
                            print("> ", end="", flush=True)
                            continue
                        
                        encrypted = self.encrypt_file_data(file_data, target_id)
                        if not encrypted:
                            print("> ", end="", flush=True)
                            continue
                        
                        self.send_json({
                            'type': 'file',
                            'from': self.client_id,
                            'target_id': target_id,
                            'file_name': os.path.basename(filename),
                            'data': encrypted
                        })
                        
                        print(f"\n[+] File '{filename}' sent to {target_id}")
                        print("> ", end="", flush=True)
                    except Exception as e:
                        print(f"\n[!] File send error: {str(e)}")
                        print("> ", end="", flush=True)
                
                elif command.startswith("/bmsg "):
                    message = ' '.join(command.split()[1:])
                    if not message:
                        print("\nUsage: /bmsg [message]")
                        print("> ", end="", flush=True)
                        continue
                    
                    with self.lock:
                        connections = list(self.connections.items())
                    
                    success_count = 0
                    for target_id, conn in connections:
                        if conn['status'] == 'established':
                            encrypted = self.encrypt_message(message, target_id)
                            if encrypted:
                                if self.send_json({
                                    'type': 'message',
                                    'from': self.client_id,
                                    'target_id': target_id,
                                    'data': encrypted
                                }):
                                    success_count += 1
                    
                    print(f"\n[+] Broadcast message sent to {success_count} clients")
                    print("> ", end="", flush=True)
                
                elif command.startswith("/bsend "):
                    filename = ' '.join(command.split()[1:])
                    if not filename:
                        print("\nUsage: /bsend [filename]")
                        print("> ", end="", flush=True)
                        continue
                    
                    if not os.path.exists(filename):
                        print(f"\n[!] File not found: {filename}")
                        print("> ", end="", flush=True)
                        continue
                    
                    try:
                        with open(filename, 'rb') as f:
                            file_data = f.read()
                        
                        if len(file_data) > 10 * 1024 * 1024:
                            print("\n[!] File too large (max 10MB)")
                            print("> ", end="", flush=True)
                            continue
                        
                        with self.lock:
                            connections = list(self.connections.items())
                        
                        success_count = 0
                        for target_id, conn in connections:
                            if conn['status'] == 'established':
                                encrypted = self.encrypt_file_data(file_data, target_id)
                                if encrypted:
                                    if self.send_json({
                                        'type': 'file',
                                        'from': self.client_id,
                                        'target_id': target_id,
                                        'file_name': os.path.basename(filename),
                                        'data': encrypted
                                    }):
                                        success_count += 1
                        
                        print(f"\n[+] Broadcast file '{filename}' sent to {success_count} clients")
                        print("> ", end="", flush=True)
                    except Exception as e:
                        print(f"\n[!] File error: {str(e)}")
                        print("> ", end="", flush=True)
                
                elif command == "/list":
                    with self.lock:
                        print("\nActive connections:")
                        for target_id, conn in self.connections.items():
                            status = conn['status']
                            if 'key_hash' in conn:
                                status += f" (key: {conn['key_hash']})"
                            print(f"- {target_id}: {status}")
                        print("> ", end="", flush=True)
                
                elif command == "/help":
                    print("\nAvailable commands:")
                    print("/connect [client_id] - Start key exchange")
                    print("/msg [client_id] [message] - Send private message")
                    print("/send [client_id] [filename] - Send private file")
                    print("/bmsg [message] - Broadcast message to all")
                    print("/bsend [filename] - Broadcast file to all")
                    print("/list - Show active connections")
                    print("/exit - Disconnect")
                    print("> ", end="", flush=True)
                
                elif command == "/exit":
                    self.socket.close()
                    print("\n[+] Disconnected")
                    return
                
                else:
                    print("\n[!] Unknown command (type /help)")
                    print("> ", end="", flush=True)
            
            except Exception as e:
                print(f"\n[!] Error: {str(e)}")
                print("> ", end="", flush=True)

if __name__ == "__main__":
    print("Starting secure chat client...")
    client = ChatClient()
    try:
        client.connect()
    except Exception as e:
        print(f"Connection failed: {str(e)}")
