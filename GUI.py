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

            # IV
            ttk.Label(settings_frame, text="IV:").grid(row=2, column=0, sticky=tk.W, pady=5)

            self.iv_format = tk.StringVar(value="Hex")
            iv_combo = ttk.Combobox(settings_frame, textvariable=self.iv_format,
                                    values=["Hex", "Текст", "Случайный"],
                                    width=8, state="readonly")
            iv_combo.grid(row=2, column=1, sticky=tk.W, padx=(5, 10), pady=5)
            iv_combo.bind('<<ComboboxSelected>>', self.on_format_changed)

            self.iv_var = tk.StringVar()
            self.iv_var.trace('w', self.validate_iv)
            self.iv_entry = ttk.Entry(settings_frame, textvariable=self.iv_var, width=50)
            self.iv_entry.grid(row=2, column=2, sticky=(tk.W, tk.E), padx=(0, 10), pady=5)

            ttk.Button(settings_frame, text="Случайный IV",
                       command=self.generate_random_iv).grid(row=2, column=3, padx=5, pady=5)

            self.iv_status = ttk.Label(settings_frame, text="", foreground="red")
            self.iv_status.grid(row=3, column=2, sticky=tk.W, pady=(0, 10))

            # Операция с текстом
            text_frame = ttk.LabelFrame(main_frame, text="Шифрование/Расшифрование", padding="10")
            text_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

            # Входной текст с контекстным меню
            ttk.Label(text_frame, text="Входной текст:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
            self.input_text = tk.Text(text_frame, width=80, height=8, undo=True)
            self.input_text.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))

            # Добавляем скроллбар к входному тексту
            input_scrollbar = ttk.Scrollbar(text_frame, command=self.input_text.yview)
            input_scrollbar.grid(row=1, column=3, sticky=(tk.N, tk.S), pady=(0, 10))
            self.input_text.config(yscrollcommand=input_scrollbar.set)

            # Кнопки действий
            btn_frame = ttk.Frame(text_frame)
            btn_frame.grid(row=2, column=0, columnspan=4, pady=(0, 10))

            ttk.Button(btn_frame, text="Шифровать", command=self.encrypt).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="Расшифровать", command=self.decrypt).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="Очистить поля", command=self.clear_fields).pack(side=tk.LEFT, padx=5)

            # Результат с контекстным меню
            ttk.Label(text_frame, text="Результат:").grid(row=3, column=0, sticky=tk.W, pady=(0, 5))
            self.output_text = tk.Text(text_frame, width=80, height=8, state="normal")
            self.output_text.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E))

            # Добавление скроллбар к результату
            output_scrollbar = ttk.Scrollbar(text_frame, command=self.output_text.yview)
            output_scrollbar.grid(row=4, column=3, sticky=(tk.N, tk.S))
            self.output_text.config(yscrollcommand=output_scrollbar.set)

            # Поле результата только для чтения
            self.output_text.bind("<Key>", lambda e: "break")  # Блокируем ввод с клавиатуры

            # Статус
            self.status_var = tk.StringVar(value="Введите ключ и IV")
            status_label = ttk.Label(main_frame, textvariable=self.status_var,
                                     relief=tk.SUNKEN, padding=(5, 5))
            status_label.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(10, 0))

            # Добавление контекстное меню для копирования/вставки
            self.create_context_menu()

            # Настройка растягивания
            main_frame.columnconfigure(0, weight=1)
            settings_frame.columnconfigure(2, weight=1)
            text_frame.columnconfigure(0, weight=1)

    def create_context_menu(self):
        """Создание контекстного меню для копирования/вставки"""
        # Меню для входного текста: копировать/вставить/вырезать
        self.input_menu = tk.Menu(self.root, tearoff=0)
        self.input_menu.add_command(label="Копировать", command=lambda: self.copy_text(self.input_text))
        self.input_menu.add_command(label="Вставить", command=lambda: self.paste_text(self.input_text))
        self.input_menu.add_command(label="Вырезать", command=lambda: self.cut_text(self.input_text))
        self.input_menu.add_separator()
        self.input_menu.add_command(label="Выделить всё", command=lambda: self.select_all(self.input_text))

        # Меню для результата
        self.output_menu = tk.Menu(self.root, tearoff=0)
        self.output_menu.add_command(label="Копировать", command=lambda: self.copy_text(self.output_text))
        self.output_menu.add_separator()
        self.output_menu.add_command(label="Выделить всё", command=lambda: self.select_all(self.output_text))

        # Привязка меню к правой кнопке мыши
        self.input_text.bind("<Button-3>", lambda e: self.show_context_menu(e, self.input_menu))
        self.output_text.bind("<Button-3>", lambda e: self.show_context_menu(e, self.output_menu))

        # Горячие клавиши
        self.input_text.bind("<Control-c>", lambda e: self.copy_text(self.input_text))
        self.input_text.bind("<Control-v>", lambda e: self.paste_text(self.input_text))
        self.input_text.bind("<Control-x>", lambda e: self.cut_text(self.input_text))
        self.input_text.bind("<Control-a>", lambda e: self.select_all(self.input_text))

        self.output_text.bind("<Control-c>", lambda e: self.copy_text(self.output_text))
        self.output_text.bind("<Control-a>", lambda e: self.select_all(self.output_text))

    def show_context_menu(self, event, menu):
        """Показать контекстное меню"""
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def copy_text(self, text_widget):
        """Копировать текст"""
        try:
            text = text_widget.get("sel.first", "sel.last")
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
        except tk.TclError:
            pass  # Ничего не выделено

    def paste_text(self, text_widget):
        """Вставить текст"""
        try:
            text = self.root.clipboard_get()
            text_widget.insert(tk.INSERT, text)
        except tk.TclError:
            pass  # Буфер пуст

    def cut_text(self, text_widget):
        """Вырезать текст"""
        try:
            text = text_widget.get("sel.first", "sel.last")
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            text_widget.delete("sel.first", "sel.last")
        except tk.TclError:
            pass  # Ничего не выделено

    def select_all(self, text_widget):
        """Выделить весь текст"""
        text_widget.tag_add(tk.SEL, "1.0", tk.END)
        text_widget.mark_set(tk.INSERT, "1.0")
        text_widget.see(tk.INSERT)