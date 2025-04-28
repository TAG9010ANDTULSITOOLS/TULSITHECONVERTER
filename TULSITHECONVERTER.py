# TULSITHECONVERTER
# Licensed under the TAG9010 LICENSE
# (See LICENSE file for full license text.)

# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from tkinter import scrolledtext
from tkinter import Menu
from tkinter import Toplevel
import os
import platform
import subprocess
import sys
import tempfile
import shutil
import base64
import traceback
import threading
import queue
import textwrap
import datetime
import hashlib

# --- Cryptography Imports ---
try:
    from Crypto.Cipher import AES
    from Crypto.Cipher import ChaCha20
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Signature import pss
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    class AES: pass
    class ChaCha20: pass
    class PBKDF2: pass
    class pss: pass
    class SHA256: pass
    class RSA: pass
    def get_random_bytes(n): return os.urandom(n)
    print("WARNING: pycryptodome not installed. Install it using: pip install pycryptodome")

# --- Constants ---
APP_TITLE = "TULSITHECONVERTER"
APP_VERSION = "2.0.0"
DEFAULT_GEOMETRY = "900x950"
MIN_HEIGHT = 900
PADDING = 10
DEFAULT_OUTPUT_DIR_NAME = "tulsi_output"
PBKDF2_ITERATIONS = 260000
LOG_FILENAME_SUFFIX = "_build_log.txt"
HASH_DISPLAY_LENGTH = 12
OBFUSCATED_INTERNAL_KEY_B64 = base64.b64encode(b"TULSITHECONVERTER_INTERNAL_KEY").decode('utf-8')
# --- Encryption Module Loader ---
class EncryptionModuleAES:
    def __init__(self, password, salt=None):
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("pycryptodome is required for AES encryption.")
        if not isinstance(password, str):
            raise TypeError("Password must be a string.")
        self.password = password.encode('utf-8')
        self.salt = salt if salt else get_random_bytes(16)
        self.key = PBKDF2(self.password, self.salt, dkLen=32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

    def encrypt_data(self, plaintext_bytes):
        cipher = AES.new(self.key, AES.MODE_GCM)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
        return self.salt + nonce + tag + ciphertext

    def decrypt_data(self, encrypted_data_package):
        if len(encrypted_data_package) < 48:
            raise ValueError("Invalid AES encrypted data.")
        salt = encrypted_data_package[:16]
        nonce = encrypted_data_package[16:32]
        tag = encrypted_data_package[32:48]
        ciphertext = encrypted_data_package[48:]
        key = PBKDF2(self.password, salt, dkLen=32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

class EncryptionModuleChaCha20:
    def __init__(self, password, salt=None):
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("pycryptodome is required for ChaCha20 encryption.")
        if not isinstance(password, str):
            raise TypeError("Password must be a string.")
        self.password = password.encode('utf-8')
        self.salt = salt if salt else get_random_bytes(16)
        self.key = PBKDF2(self.password, self.salt, dkLen=32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

    def encrypt_data(self, plaintext_bytes):
        nonce = get_random_bytes(8)
        cipher = ChaCha20.new(key=self.key, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext_bytes)
        return self.salt + nonce + ciphertext

    def decrypt_data(self, encrypted_data_package):
        if len(encrypted_data_package) < 24:
            raise ValueError("Invalid ChaCha20 encrypted data.")
        salt = encrypted_data_package[:16]
        nonce = encrypted_data_package[16:24]
        ciphertext = encrypted_data_package[24:]
        key = PBKDF2(self.password, salt, dkLen=32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        return cipher.decrypt(ciphertext)
# --- Signature Module ---
class SignatureModule:
    def __init__(self, private_key_path, password=None):
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("pycryptodome is required for signing.")
        self.private_key_path = private_key_path
        try:
            with open(self.private_key_path, 'rb') as f:
                key_data = f.read()
            self.private_key = RSA.import_key(key_data, passphrase=password)
            if not self.private_key.has_private():
                raise ValueError("Provided key is not a private key.")
        except Exception as e:
            raise ValueError(f"Failed to load private key: {e}")

    def sign_data(self, data_bytes):
        if not self.private_key:
            raise RuntimeError("Private key not loaded.")
        try:
            h = SHA256.new(data_bytes)
            signer = pss.new(self.private_key)
            return signer.sign(h)
        except Exception as e:
            raise RuntimeError(f"Failed to sign data: {e}")

# --- Utility: Hash Calculation ---
def calculate_sha256(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

# --- Utility: Get Working Directory ---
def get_working_dir():
    return os.getcwd()

# --- Placeholder Build for Android ---
def placeholder_build_android(source_code, app_name, icon_path, output_dir, progress_queue=None):
    if progress_queue:
        progress_queue.put("Placeholder: Android Build (not implemented)")
    return True
# --- Main Application Class (TULSI THE CONVERTER) ---
class AppConverter(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_TITLE} v{APP_VERSION}")
        self.geometry(DEFAULT_GEOMETRY)
        self.minsize(750, MIN_HEIGHT)

        self.style = ttk.Style(self)
        themes = self.style.theme_names()
        if 'clam' in themes:
            self.style.theme_use('clam')

        # Core Variables
        self.icon_path = tk.StringVar()
        self.encryption_method = tk.StringVar(value="None")
        self.app_name = tk.StringVar(value="MyNewApp")
        self.status_text = tk.StringVar()
        self.output_directory = tk.StringVar()
        self.private_key_path = tk.StringVar()
        self.public_key_path = tk.StringVar()
        self.private_key_password = tk.StringVar()
        self.publisher_info_var = tk.StringVar()
        self.allow_view_source_var = tk.BooleanVar(value=True)
        self.build_queue = queue.Queue()

        # Set default output path
        default_output = os.path.abspath(DEFAULT_OUTPUT_DIR_NAME)
        self.output_directory.set(default_output)
        self.status_text.set(f"Ready. Output: {default_output}")

        # Create UI
        self._create_widgets()

    def _create_widgets(self):
        main_frame = ttk.Frame(self, padding=PADDING)
        main_frame.pack(expand=True, fill=tk.BOTH)

        # --- Code Input ---
        code_frame = ttk.LabelFrame(main_frame, text="Paste your Code", padding=PADDING)
        code_frame.pack(fill=tk.BOTH, expand=True, pady=(0, PADDING))

        self.code_text_area = tk.Text(code_frame, wrap=tk.WORD, height=15, undo=True, relief=tk.SUNKEN, borderwidth=1)
        self.code_text_area.pack(fill=tk.BOTH, expand=True)

        code_scroll = ttk.Scrollbar(code_frame, orient=tk.VERTICAL, command=self.code_text_area.yview)
        self.code_text_area.config(yscrollcommand=code_scroll.set)
        code_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        # --- Basic Config ---
        config_frame = ttk.LabelFrame(main_frame, text="Basic Configuration", padding=PADDING)
        config_frame.pack(fill=tk.BOTH, expand=False, pady=(0, PADDING))

        ttk.Label(config_frame, text="App Name:").grid(row=0, column=0, sticky=tk.W, padx=(0, PADDING))
        self.app_name_entry = ttk.Entry(config_frame, textvariable=self.app_name, width=40)
        self.app_name_entry.grid(row=0, column=1, sticky=tk.EW)

        ttk.Label(config_frame, text="App Icon:").grid(row=1, column=0, sticky=tk.W, padx=(0, PADDING))
        self.icon_entry = ttk.Entry(config_frame, textvariable=self.icon_path, width=40, state='readonly')
        self.icon_entry.grid(row=1, column=1, sticky=tk.EW)

        icon_button = ttk.Button(config_frame, text="Choose Icon...", command=self._choose_icon)
        icon_button.grid(row=1, column=2, sticky=tk.W)

        ttk.Label(config_frame, text="Output Folder:").grid(row=2, column=0, sticky=tk.W, padx=(0, PADDING))
        self.output_entry = ttk.Entry(config_frame, textvariable=self.output_directory, width=40, state='readonly')
        self.output_entry.grid(row=2, column=1, sticky=tk.EW)

        output_button = ttk.Button(config_frame, text="Choose Folder...", command=self._choose_output_folder)
        output_button.grid(row=2, column=2, sticky=tk.W)

        # --- Encryption Settings ---
        encrypt_frame = ttk.LabelFrame(main_frame, text="Encryption Settings", padding=PADDING)
        encrypt_frame.pack(fill=tk.BOTH, expand=False, pady=(0, PADDING))

        ttk.Label(encrypt_frame, text="Encryption Method:").grid(row=0, column=0, sticky=tk.W, padx=(0, PADDING))
        enc_options = ["None", "AES-GCM", "ChaCha20", "Hybrid RSA+AES", "Hybrid RSA+ChaCha20"]
        self.encrypt_combo = ttk.Combobox(encrypt_frame, textvariable=self.encryption_method, values=enc_options, state='readonly', width=40)
        self.encrypt_combo.grid(row=0, column=1, sticky=tk.EW)
        self.encrypt_combo.current(0)

        # --- Action Buttons ---
        action_frame = ttk.Frame(main_frame, padding=(0, PADDING))
        action_frame.pack()

        build_button = ttk.Button(action_frame, text="Build Application", command=self._start_build_process)
        build_button.pack(side=tk.LEFT, padx=(0, 10))

        view_source_button = ttk.Button(action_frame, text="View Current Source", command=self._open_view_source_window)
        view_source_button.pack(side=tk.LEFT)

        # --- Status Bar ---
        status_bar = ttk.Label(self, textvariable=self.status_text, relief=tk.SUNKEN, anchor=tk.W, padding=(5, 3))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    def _choose_icon(self):
        path = filedialog.askopenfilename(title="Select Icon File", filetypes=[("Icon files", "*.ico *.png *.icns"), ("All files", "*.*")])
        if path:
            self.icon_path.set(path)
            self.status_text.set(f"Selected icon: {os.path.basename(path)}")

    def _choose_output_folder(self):
        path = filedialog.askdirectory(title="Select Output Folder")
        if path:
            self.output_directory.set(path)
            self.status_text.set(f"Selected output directory: {path}")

    def _open_view_source_window(self):
        code = self.code_text_area.get("1.0", tk.END)
        viewer = SourceViewerWindow(self, code)
        viewer.grab_set()

    def _start_build_process(self):
        source_code = self.code_text_area.get("1.0", tk.END).strip()
        if not source_code:
            messagebox.showerror("Error", "Please paste some code to package.")
            return

        app_name = self.app_name.get().strip()
        if not app_name:
            messagebox.showerror("Error", "Application name is required.")
            return

        output_dir = self.output_directory.get().strip()
        if not output_dir or not os.path.isdir(output_dir):
            messagebox.showerror("Error", "Valid output folder is required.")
            return

        self.status_text.set("Starting build...")
        threading.Thread(target=self._build_worker, args=(source_code, app_name, output_dir, self.icon_path.get(), self.encryption_method.get()), daemon=True).start()

    def _build_worker(self, source_code, app_name, output_dir, icon_path, encryption_method):
        try:
            # Placeholder: Save to output directory for now
            output_file = os.path.join(output_dir, f"{app_name}.py")
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(source_code)
            self.status_text.set(f"Build successful: {output_file}")
        except Exception as e:
            self.status_text.set(f"Build failed: {e}")
            traceback.print_exc()
# --- Source Viewer Window (View Source + Blind Mode) ---
class SourceViewerWindow(tk.Toplevel):
    def __init__(self, parent, code_text):
        super().__init__(parent)
        self.title("View Source Code")
        self.geometry("800x600")
        self.code_text = code_text
        self.original_code = code_text

        main_frame = ttk.Frame(self, padding=PADDING)
        main_frame.pack(expand=True, fill=tk.BOTH)

        # Text Area
        self.text_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, font=("Courier", 10))
        self.text_area.pack(expand=True, fill=tk.BOTH)
        self.text_area.insert('1.0', self.code_text)
        self.text_area.config(state=tk.DISABLED)

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=(10, 0))

        blind_button = ttk.Button(btn_frame, text="TULSI IN BLIND MODE", command=self._open_blind_mode)
        blind_button.pack(side=tk.LEFT, padx=(0,10))

        close_button = ttk.Button(btn_frame, text="Close", command=self.destroy)
        close_button.pack(side=tk.LEFT)

    def _open_blind_mode(self):
        blind_window = BlindModeEditor(self, self.original_code)
        blind_window.grab_set()
# --- Blind Mode Editor Window ---
class BlindModeEditor(tk.Toplevel):
    def __init__(self, parent, original_code):
        super().__init__(parent)
        self.title("TULSI IN BLIND MODE")
        self.geometry("800x600")
        self.original_code = original_code

        main_frame = ttk.Frame(self, padding=PADDING)
        main_frame.pack(expand=True, fill=tk.BOTH)

        # Text Area
        self.text_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, font=("Courier", 10))
        self.text_area.pack(expand=True, fill=tk.BOTH)
        self.text_area.insert('1.0', self.original_code)

        # Bind key events
        self.text_area.bind("<Key>", self._on_key_press)

        # Info Label
        self.info_label = ttk.Label(main_frame, text="Status: Ready")
        self.info_label.pack(pady=(5, 0))

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=(10, 0))

        undo_button = ttk.Button(btn_frame, text="Undo Changes", command=self._undo_changes)
        undo_button.pack(side=tk.LEFT, padx=(0,10))

        close_button = ttk.Button(btn_frame, text="Close", command=self.destroy)
        close_button.pack(side=tk.LEFT)

    def _on_key_press(self, event):
        allowed_keys = {'BackSpace', 'space', 'Return'}
        allowed_symbols = {'"', "'", ':', ';', '/', '\\', '.', ',', '(', ')', '[', ']', '{', '}'}
        char = event.char

        if event.keysym in allowed_keys:
            self._check_syntax()
            return
        elif char in allowed_symbols:
            self._check_syntax()
            return
        else:
            return "break"  # Block all other typing

    def _check_syntax(self):
        code = self.text_area.get('1.0', tk.END)
        try:
            compile(code, "<string>", "exec")
            self.info_label.config(text="Status: Syntax OK ✅", foreground="green")
        except Exception:
            self.info_label.config(text="Status: Syntax Error ❌", foreground="red")

    def _undo_changes(self):
        self.text_area.delete('1.0', tk.END)
        self.text_area.insert('1.0', self.original_code)
        self.info_label.config(text="Status: Ready", foreground="black")
# --- Main Execution Block ---
if __name__ == "__main__":
    try:
        # Optional: set High DPI awareness for Windows
        if platform.system() == "Windows":
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass  # Not critical

    app = AppConverter()
    app.mainloop()



