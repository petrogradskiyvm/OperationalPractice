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