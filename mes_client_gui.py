import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog
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

class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SMTS GUI")
        self.root.geometry("800x600")
        
        # Основные параметры
        self.server_host = 'YOUR_SERVER_IP'
        self.server_port = 5555
        self.client_id = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connections = {}
        self.dh_private_keys = {}
        self.lock = threading.Lock()
        self.handshake_secret = "SECRET_HANDSHAKE_KEY"  # Должен совпадать с серверным
        
        # Параметры Диффи-Хеллмана
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
        
        # Создание интерфейса
        self.create_widgets()
        
        # Подключение к серверу
        self.connect_to_server()


    def create_widgets(self):
        # Основной контейнер с двумя колонками
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Левая колонка (40% ширины)
        left_column = ttk.Frame(main_container, width=int(1024*0.4))
        left_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=False)
        left_column.pack_propagate(False)
        
        # Правая колонка (60% ширины)
        right_column = ttk.Frame(main_container)
        right_column.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Левая колонка: Контакты + Кнопка подключения
        
        # Контейнер для контактов (с фиксированной минимальной высотой)
        contacts_frame = ttk.LabelFrame(left_column, text="Контакты", padding="5")
        contacts_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview для контактов с вертикальным скроллингом
        self.contacts_list = ttk.Treeview(contacts_frame, columns=('id', 'status', 'key'), show='headings')
        self.contacts_list.heading('id', text='ID')
        self.contacts_list.heading('status', text='Статус')
        self.contacts_list.heading('key', text='Ключ')
        self.contacts_list.column('id', width=120)
        self.contacts_list.column('status', width=80)
        self.contacts_list.column('key', width=80)
        
        scrollbar = ttk.Scrollbar(contacts_frame, orient="vertical", command=self.contacts_list.yview)
        self.contacts_list.configure(yscrollcommand=scrollbar.set)
        
        self.contacts_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Фрейм для кнопки подключения (с фиксированной высотой)
        connect_frame = ttk.Frame(left_column, height=50)
        connect_frame.pack(side=tk.BOTTOM, fill=tk.X, expand=False)
        
        connect_button = ttk.Button(connect_frame, text="Подключиться", command=self.connect_to_client)
        connect_button.pack(pady=5, padx=20, fill=tk.X, expand=True)

        # Правая колонка: Информация + Сообщения + Ввод
        
        # Блок информации (верхний)
        info_frame = ttk.LabelFrame(right_column, text="Информация", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.client_info = ttk.Label(info_frame, text="Не подключено")
        self.client_info.pack()
        
        # Блок сообщений (70% от оставшейся высоты)
        msg_frame = ttk.LabelFrame(right_column, text="Сообщения", padding="10")
        msg_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.message_area = scrolledtext.ScrolledText(msg_frame, wrap=tk.WORD, state='disabled')
        self.message_area.pack(fill=tk.BOTH, expand=True)
        
        # Блок ввода (нижний)
        input_frame = ttk.LabelFrame(right_column, text="Ввод сообщения", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Поле ввода сообщения
        self.message_entry = ttk.Entry(input_frame)
        self.message_entry.pack(fill=tk.X, pady=(0, 10))
        self.message_entry.bind("<Return>", self.send_message_event)
        
        # Кнопки отправки
        button_frame = ttk.Frame(input_frame)
        button_frame.pack(fill=tk.X)
        
        send_button = ttk.Button(button_frame, text="Отправить", command=self.send_message)
        send_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        file_button = ttk.Button(button_frame, text="Отправить файл", command=self.send_file)
        file_button.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        
        # Меню
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Выход", command=self.on_closing)
        menubar.add_cascade(label="Файл", menu=file_menu)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="О программе", command=self.show_about)
        menubar.add_cascade(label="Помощь", menu=help_menu)
    
    def connect_to_server(self):
        try:
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
            self.client_info.config(text=f"ID: {self.client_id}")
            self.add_message(f"Подключено как {self.client_id}")
            
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Ошибка подключения", f"Не удалось подключиться к серверу: {str(e)}")
            self.root.after(1000, self.root.destroy)
    
    def send_json(self, message):
        try:
            message_str = json.dumps(message)
            message_len = struct.pack('>I', len(message_str))
            self.socket.sendall(message_len + message_str.encode('utf-8'))
            return True
        except Exception as e:
            self.add_message(f"[!] Ошибка отправки: {str(e)}", error=True)
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
            self.add_message(f"[!] Ошибка получения: {str(e)}", error=True)
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
            self.add_message("[!] Нельзя подключиться к себе", error=True)
            return

        with self.lock:
            if target_id in self.connections:
                self.add_message("[!] Подключение уже существует", error=True)
                return
            
            self.connections[target_id] = {'status': 'pending'}
            self.update_contacts_list()
        
        private_key = random.getrandbits(2048) % self.dh_prime
        public_key = pow(self.dh_base, private_key, self.dh_prime)
        
        with self.lock:
            self.dh_private_keys[target_id] = private_key
        
        self.add_message(f"[DH] Начало обмена ключами с {target_id}")
        
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
                    self.add_message("[!] Отсутствует приватный ключ для обмена DH", error=True)
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
                self.update_contacts_list()
            
            self.add_message(f"[DH] Обмен ключами с {target_id} завершен!")
            self.add_message(f"[DH] Отпечаток ключа: {key_hash}")
        except Exception as e:
            self.add_message(f"[!] Ошибка обмена ключами: {str(e)}", error=True)
    
    def encrypt_message(self, message, target_id):
        with self.lock:
            conn = self.connections.get(target_id)
            if not conn or conn['status'] != 'established':
                self.add_message(f"[!] Нет установленного соединения с {target_id}", error=True)
                return None
            aes_key = conn['key']
        
        try:
            message_bytes = message.encode('utf-8')
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(message_bytes, AES.block_size))
            return base64.b64encode(iv + ct_bytes).decode('utf-8')
        except Exception as e:
            self.add_message(f"[!] Ошибка шифрования: {str(e)}", error=True)
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
                raise ValueError("Недопустимая длина шифротекста")
                
            iv, ct = data[:16], data[16:]
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt.decode('utf-8')
        except ValueError as e:
            self.add_message(f"[!] Ошибка дешифрования (ключ: {conn.get('key_hash', 'unknown')}): {str(e)}", error=True)
            return None
        except Exception as e:
            self.add_message(f"[!] Ошибка дешифрования: {str(e)}", error=True)
            return None
    
    def encrypt_file_data(self, file_data, target_id):
        with self.lock:
            conn = self.connections.get(target_id)
            if not conn or conn['status'] != 'established':
                self.add_message(f"[!] Нет установленного соединения с {target_id}", error=True)
                return None
            aes_key = conn['key']
        
        try:
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(file_data, AES.block_size))
            return base64.b64encode(iv + ct_bytes).decode('utf-8')
        except Exception as e:
            self.add_message(f"[!] Ошибка шифрования файла: {str(e)}", error=True)
            return None
    
    def decrypt_file_data(self, encrypted_data, sender_id):
        with self.lock:
            conn = self.connections.get(sender_id)
            if not conn or conn['status'] != 'established':
                self.add_message(f"[!] Нет установленного соединения с {sender_id}", error=True)
                return None
            
            aes_key = conn['key']
        
        try:
            data = base64.b64decode(encrypted_data)
            if len(data) < AES.block_size:
                raise ValueError("Данные слишком короткие для IV")
                
            iv = data[:AES.block_size]
            ct = data[AES.block_size:]
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt
        except ValueError as e:
            self.add_message(f"[!] Ошибка дешифрования файла (ключ: {conn.get('key_hash', 'unknown')}): {str(e)}", error=True)
            return None
        except Exception as e:
            self.add_message(f"[!] Ошибка дешифрования файла: {str(e)}", error=True)
            return None
    
    def receive_messages(self):
        while True:
            try:
                message = self.receive_json()
                if not message:
                    break

                if message.get('type') == 'dh_init':
                    self.add_message(f"\n[DH] Получен запрос обмена ключами от {message['from']}")
                    
                    try:
                        prime = int(message['prime'])
                        base = int(message['base'])
                        their_public_key = int(message['public_key'])
                    except:
                        self.add_message("[!] Неверные параметры DH", error=True)
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
                            self.update_contacts_list()
                        
                        self.add_message(f"[DH] Обмен ключами с {message['from']} завершен")
                        self.add_message(f"[DH] Отпечаток ключа: {key_hash}")
                    except Exception as e:
                        self.add_message(f"[!] Ошибка вычисления ключа: {str(e)}", error=True)

                elif message.get('type') == 'dh_response':
                    self.add_message(f"\n[DH] Получен ответ от {message['from']}")
                    self.complete_dh_exchange(message['from'], message['public_key'], is_initiator=True)

                elif message.get('type') == 'message':
                    decrypted = self.decrypt_message(message['data'], message['from'])
                    if decrypted:
                        self.add_message(f"\n[Приватно от {message['from']}]: {decrypted}")

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
                        
                        self.add_message(f"\n[Файл от {message['from']}] Сохранен как: {file_name} (размер: {len(file_data)} байт)")
                        self.add_message(f"Файл сохранен в: {os.path.abspath(file_name)}")

                elif message.get('type') == 'broadcast_msg':
                    decrypted = self.decrypt_message(message['data'], message['from'])
                    if decrypted:
                        self.add_message(f"\n[Broadcast от {message['from']}]: {decrypted}")

                elif message.get('type') == 'broadcast_file':
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
                        
                        self.add_message(f"\n[Broadcast файл от {message['from']}] Сохранен как: {file_name} (размер: {len(file_data)} байт)")
                        self.add_message(f"Файл сохранен в: {os.path.abspath(file_name)}")

            except Exception as e:
                self.add_message(f"[!] Ошибка получения: {str(e)}", error=True)
                break
    
    def add_message(self, message, error=False):
        self.root.after(0, self._add_message, message, error)
    
    def _add_message(self, message, error):
        self.message_area.config(state='normal')
        tag = "error" if error else "normal"
        self.message_area.insert(tk.END, message + "\n", tag)
        self.message_area.config(state='disabled')
        self.message_area.see(tk.END)
    
    def update_contacts_list(self):
        self.root.after(0, self._update_contacts_list)
    
    def _update_contacts_list(self):
        self.contacts_list.delete(*self.contacts_list.get_children())
        with self.lock:
            for target_id, conn in self.connections.items():
                status = conn['status']
                key_hash = conn.get('key_hash', '')
                self.contacts_list.insert('', 'end', values=(target_id, status, key_hash))
    
    def connect_to_client(self):
        target_id = simpledialog.askstring("Подключение", "Введите ID клиента:")
        if target_id:
            self.start_dh_exchange(target_id)
    
    def send_message(self):
        message = self.message_entry.get()
        if not message:
            return
        
        selected = self.contacts_list.selection()
        if not selected:
            messagebox.showwarning("Ошибка", "Выберите получателя из списка")
            return
        
        target_ids = [self.contacts_list.item(item, 'values')[0] for item in selected]
        
        if len(target_ids) == 1:
            # Одиночное сообщение
            target_id = target_ids[0]
            encrypted = self.encrypt_message(message, target_id)
            
            if not encrypted:
                return
            
            self.send_json({
                'type': 'message',
                'from': self.client_id,
                'target_id': target_id,
                'data': encrypted
            })
            
            self.add_message(f"\n[Я → {target_id}]: {message}")
        else:
            # Broadcast сообщение
            for target_id in target_ids:
                encrypted = self.encrypt_message(message, target_id)
                
                if not encrypted:
                    continue
                
                self.send_json({
                    'type': 'broadcast_msg',
                    'from': self.client_id,
                    'target_id': target_id,
                    'data': encrypted
                })
            
            self.add_message(f"\n[Broadcast → {', '.join(target_ids)}]: {message}")
        
        self.message_entry.delete(0, tk.END)
    
    def send_message_event(self, event):
        self.send_message()
    
    def send_file(self):
        selected = self.contacts_list.selection()
        if not selected:
            messagebox.showwarning("Ошибка", "Выберите получателя из списка")
            return
        
        target_ids = [self.contacts_list.item(item, 'values')[0] for item in selected]
        filename = filedialog.askopenfilename(title="Выберите файл для отправки")
        
        if not filename:
            return
        
        try:
            with open(filename, 'rb') as f:
                file_data = f.read()
            
            if len(file_data) > 10 * 1024 * 1024:
                messagebox.showerror("Ошибка", "Файл слишком большой (максимум 10МБ)")
                return
            
            if len(target_ids) == 1:
                # Одиночный файл
                target_id = target_ids[0]
                encrypted = self.encrypt_file_data(file_data, target_id)
                if not encrypted:
                    return
                
                self.send_json({
                    'type': 'file',
                    'from': self.client_id,
                    'target_id': target_id,
                    'file_name': os.path.basename(filename),
                    'data': encrypted
                })
                
                self.add_message(f"\n[+] Файл '{os.path.basename(filename)}' отправлен: {target_id}")
            else:
                # Broadcast файл
                for target_id in target_ids:
                    encrypted = self.encrypt_file_data(file_data, target_id)
                    if not encrypted:
                        continue
                    
                    self.send_json({
                        'type': 'file',
                        'from': self.client_id,
                        'target_id': target_id,
                        'file_name': os.path.basename(filename),
                        'data': encrypted
                    })
                
                self.add_message(f"\n[+] Broadcast файл '{os.path.basename(filename)}' отправлен: {', '.join(target_ids)}")
        except Exception as e:
            self.add_message(f"[!] Ошибка отправки файла: {str(e)}", error=True)
    
    def show_about(self):
        messagebox.showinfo("О программе", "SMTS GUI\nВерсия 1.0.0")
    
    def on_closing(self):
        if messagebox.askokcancel("Выход", "Вы уверены, что хотите выйти?"):
            try:
                self.socket.close()
            except:
                pass
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientGUI(root)
    
    # Настройка тегов для сообщений
    app.message_area.tag_config("normal", foreground="black")
    app.message_area.tag_config("error", foreground="red")
    
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.state('zoomed')
    root.mainloop()
