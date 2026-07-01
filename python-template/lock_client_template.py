import socketio
import base64
import json
import time
import os
import sys
import platform
import logging
import threading
import tkinter as tk
import keyboard
from Crypto.Cipher import AES
import requests

# CONFIGURATION
API_KEY = "{{API_KEY}}"
ACCOUNT_ID = "{{ACCOUNT_ID}}"
DEVICE_NAME = "{{DEVICE_NAME}}"
SERVER_URL = "{{SERVER_URL}}"

class OathNetClient:
    def __init__(self):
        self.api_key = API_KEY
        self.account_id = ACCOUNT_ID
        self.device_name = DEVICE_NAME
        self.device_id = None
        self.session_key = None
        self.sio = socketio.Client()
        self.lock_screen = None
        self.is_locked = False
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("OathNet")

    def encrypt(self, data):
        cipher = AES.new(self.session_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(json.dumps(data).encode())
        return {
            'encrypted': base64.b64encode(ciphertext).decode(),
            'iv': base64.b64encode(cipher.nonce).decode(),
            'tag': base64.b64encode(tag).decode()
        }
    
    def decrypt(self, encrypted_data):
        cipher = AES.new(self.session_key, AES.MODE_GCM, nonce=base64.b64decode(encrypted_data['iv']))
        decrypted = cipher.decrypt_and_verify(base64.b64decode(encrypted_data['encrypted']), base64.b64decode(encrypted_data['tag']))
        return json.loads(decrypted.decode())

    def register(self):
        try:
            resp = requests.post(f"{SERVER_URL}/api/v1/devices", 
                headers={'X-API-Key': self.api_key},
                json={'name': self.device_name, 'deviceType': platform.system(), 'hostname': platform.node()}
            )
            if resp.status_code == 201:
                data = resp.json()
                self.device_id = data['device']['deviceId']
                self.session_key = base64.b64decode(data['device']['sessionKey'])
                return True
        except: pass
        return False

    def toggle_lock(self, status):
        if status and not self.is_locked:
            self.is_locked = True
            threading.Thread(target=self.show_overlay).start()
            self.block_keys()
        elif not status and self.is_locked:
            self.is_locked = False
            if self.lock_screen:
                self.lock_screen.after(0, self.lock_screen.destroy)
            self.unblock_keys()

    def show_overlay(self):
        self.lock_screen = tk.Tk()
        self.lock_screen.attributes('-fullscreen', True)
        self.lock_screen.attributes('-topmost', True)
        self.lock_screen.configure(bg='black')
        
        label = tk.Label(self.lock_screen, text="DEVICE LOCKED BY OATHNET", fg="white", bg="black", font=("Arial", 32, "bold"))
        label.place(relx=0.5, rely=0.4, anchor="center")
        
        timer_label = tk.Label(self.lock_screen, text="24:00:00", fg="gray", bg="black", font=("Arial", 24))
        timer_label.place(relx=0.5, rely=0.5, anchor="center")
        
        self.lock_screen.mainloop()

    def block_keys(self):
        for key in ['alt', 'tab', 'win', 'esc', 'f4']:
            keyboard.block_key(key)

    def unblock_keys(self):
        keyboard.unhook_all()

    def run(self):
        if not self.register(): return
        
        @self.sio.on('connect')
        def on_connect():
            self.sio.emit('device:auth', self.encrypt({'deviceId': self.device_id, 'apiKey': self.api_key, 'type': 'authenticate'}))

        @self.sio.on('command')
        def on_command(data):
            try:
                cmd = self.decrypt(data)
                if cmd['command'] == 'lock': self.toggle_lock(True)
                if cmd['command'] == 'unlock': self.toggle_lock(False)
            except: pass

        self.sio.connect(SERVER_URL)
        self.sio.wait()

if __name__ == "__main__":
    OathNetClient().run()