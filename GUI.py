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