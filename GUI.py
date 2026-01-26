"""
GUI для шифра Sosemanuk
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import os
import hashlib
from sosemanuk import CustomSosemanuk, MIN_KEY_LEN, MAX_KEY_LEN, MAX_IV_LEN


class SosemanukGUI:
    """Интерфейс для шифрования Sosemanuk"""

    def __init__(self, root):
        self.root = root
        self.root.title("Криптоалгоритм SOSEMANUK")
        self.root.geometry("700x600")

        # Текущие настройки
        self.key = b''
        self.iv = b''

        # Создание интерфейса
        self.create_widgets()

        def create_widgets(self):
            """Создание всех виджетов интерфейса"""
            # Основной контейнер
            main_frame = ttk.Frame(self.root, padding="10")
            main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

            # Настройки шифрования
            settings_frame = ttk.LabelFrame(main_frame, text="Настройки шифрования", padding="10")
            settings_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

            # Ключ
            ttk.Label(settings_frame, text="Ключ:").grid(row=0, column=0, sticky=tk.W, pady=5)

            self.key_format = tk.StringVar(value="Hex")
            key_combo = ttk.Combobox(settings_frame, textvariable=self.key_format,
                                     values=["Hex", "Текст"], width=8, state="readonly")
            key_combo.grid(row=0, column=1, sticky=tk.W, padx=(5, 10), pady=5)
            key_combo.bind('<<ComboboxSelected>>', self.on_format_changed)

            self.key_var = tk.StringVar()
            self.key_var.trace('w', self.validate_key)
            key_entry = ttk.Entry(settings_frame, textvariable=self.key_var, width=50)
            key_entry.grid(row=0, column=2, sticky=(tk.W, tk.E), padx=(0, 10), pady=5)

            ttk.Button(settings_frame, text="Случайный ключ",
                       command=self.generate_random_key).grid(row=0, column=3, padx=5, pady=5)

            self.key_status = ttk.Label(settings_frame, text="", foreground="red")
            self.key_status.grid(row=1, column=2, sticky=tk.W, pady=(0, 10))