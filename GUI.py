"""
GUI для шифра Sosemanuk
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import os
import hashlib
import threading
import time
from pathlib import Path
from sosemanuk import CustomSosemanuk, MIN_KEY_LEN, MAX_KEY_LEN, MAX_IV_LEN


class SosemanukGUI:
    """GUI для криптоалгоритма Sosemanuk"""

    def __init__(self, root):
        self.root = root
        self.root.title("Криптоалгоритм SOSEMANUK")
        self.root.geometry("800x750")

        # Создание вкладок
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Текущие настройки
        self.key = b''
        self.iv = b''

        # Создание вкладок 2
        self.create_text_tab()
        self.create_file_tab()
        self.create_status_bar()

        # Инициализация
        self.update_status()

    def create_text_tab(self):
        """Вкладка для текстового шифрования"""
        text_frame = ttk.Frame(self.notebook)
        self.notebook.add(text_frame, text="Текстовое шифрование")

        # Настройки шифрования для текстовой вкладки
        self.create_settings_section(text_frame, 0, is_file_tab=False)

        # Операция с текстом
        text_ops_frame = ttk.LabelFrame(text_frame, text="Шифрование/Расшифрование текста", padding="10")
        text_ops_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        text_ops_frame.columnconfigure(0, weight=1)

        # Входной текст
        ttk.Label(text_ops_frame, text="Входной текст:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.input_text = scrolledtext.ScrolledText(text_ops_frame, width=90, height=10, undo=True)
        self.input_text.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Кнопки действий для текста
        btn_frame = ttk.Frame(text_ops_frame)
        btn_frame.grid(row=2, column=0, pady=(0, 10))

        ttk.Button(btn_frame, text="Шифровать текст", command=self.encrypt_text).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Расшифровать текст", command=self.decrypt_text).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Очистить поля", command=self.clear_text_fields).pack(side=tk.LEFT, padx=5)

        # Результат
        ttk.Label(text_ops_frame, text="Результат:").grid(row=3, column=0, sticky=tk.W, pady=(0, 5))
        self.output_text = scrolledtext.ScrolledText(text_ops_frame, width=90, height=10, state="normal")
        self.output_text.grid(row=4, column=0, sticky=(tk.W, tk.E))
        self.output_text.bind("<Key>", lambda e: "break")  # Блокируем ввод

        # Контекстное меню
        self.create_text_context_menu()

    def create_file_tab(self):
        """Вкладка для шифрования файлов"""
        file_frame = ttk.Frame(self.notebook)
        self.notebook.add(file_frame, text="Шифрование файлов")

        # Настройки шифрования для файловой вкладки
        self.create_settings_section(file_frame, 0, is_file_tab=True)

        # Операции с файлами
        file_ops_frame = ttk.LabelFrame(file_frame, text="Шифрование/Расшифрование файлов", padding="10")
        file_ops_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        file_ops_frame.columnconfigure(0, weight=1)

        # Выбор файла
        ttk.Label(file_ops_frame, text="Исходный файл:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))

        file_select_frame = ttk.Frame(file_ops_frame)
        file_select_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        self.file_path_var = tk.StringVar()
        ttk.Entry(file_select_frame, textvariable=self.file_path_var, width=70).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(file_select_frame, text="Выбрать файл", command=self.select_file).pack(side=tk.LEFT)

        # Информация о файле
        self.file_info_label = ttk.Label(file_ops_frame, text="Файл не выбран")
        self.file_info_label.grid(row=2, column=0, sticky=tk.W, pady=(0, 10))

        # Прогресс-бар
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(file_ops_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Статус операции
        self.operation_status_var = tk.StringVar(value="")
        self.operation_status_label = ttk.Label(file_ops_frame, textvariable=self.operation_status_var)
        self.operation_status_label.grid(row=4, column=0, sticky=tk.W, pady=(0, 10))

        # Кнопки действий для файлов
        btn_frame = ttk.Frame(file_ops_frame)
        btn_frame.grid(row=5, column=0, pady=(0, 10))

        ttk.Button(btn_frame, text="Шифровать файл", command=self.encrypt_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Расшифровать файл", command=self.decrypt_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Очистить", command=self.clear_file_fields).pack(side=tk.LEFT, padx=5)

        # Поддерживаемые форматы
        formats_frame = ttk.LabelFrame(file_ops_frame, text="Поддерживаемые форматы файлов", padding="10")
        formats_frame.grid(row=6, column=0, sticky=(tk.W, tk.E), pady=(10, 0))

        formats_text = """• Архивы: .zip, .7z, .rar, .tar, .gz
• Документы: .docx, .doc, .xlsx, .xls, .pptx, .ppt, .pdf
• Изображения: .jpg, .jpeg, .png, .bmp, .gif
• Текстовые: .txt, .csv, .xml, .json
• Исполняемые: .exe, .dll, .bin"""

        ttk.Label(formats_frame, text=formats_text, justify=tk.LEFT).pack(anchor=tk.W)

    def create_settings_section(self, parent, row, is_file_tab=False):
        """Создание секции с настройками шифрования"""
        settings_frame = ttk.LabelFrame(parent, text="Настройки шифрования", padding="10")
        settings_frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        settings_frame.columnconfigure(2, weight=1)

        # Сохранение ссылки на виджеты для каждой вкладки
        if is_file_tab:
            # Для файловой вкладки
            self.file_key_var = tk.StringVar()
            self.file_iv_var = tk.StringVar()
            key_var = self.file_key_var
            iv_var = self.file_iv_var

            # Привязка валидации
            self.file_key_var.trace('w', lambda *args: self.validate_key(is_file_tab=True))
            self.file_iv_var.trace('w', lambda *args: self.validate_iv(is_file_tab=True))
        else:
            # Для текстовой вкладки
            self.text_key_var = tk.StringVar()
            self.text_iv_var = tk.StringVar()
            key_var = self.text_key_var
            iv_var = self.text_iv_var

            # Привязываем валидацию
            self.text_key_var.trace('w', lambda *args: self.validate_key(is_file_tab=False))
            self.text_iv_var.trace('w', lambda *args: self.validate_iv(is_file_tab=False))

        # Ключ
        ttk.Label(settings_frame, text="Ключ:").grid(row=0, column=0, sticky=tk.W, pady=5)

        key_format_var = tk.StringVar(value="Hex")
        key_combo = ttk.Combobox(settings_frame, textvariable=key_format_var,
                                values=["Hex", "Текст"], width=8, state="readonly")
        key_combo.grid(row=0, column=1, sticky=tk.W, padx=(5, 10), pady=5)
        key_combo.bind('<<ComboboxSelected>>', lambda e, tab=is_file_tab: self.on_format_changed(tab))

        key_entry = ttk.Entry(settings_frame, textvariable=key_var, width=60)
        key_entry.grid(row=0, column=2, sticky=(tk.W, tk.E), padx=(0, 10), pady=5)

        # Кнопка случайного ключа для текущей вкладки
        ttk.Button(settings_frame, text="Случайный ключ",
                  command=lambda: self.generate_random_key(is_file_tab)).grid(row=0, column=3, padx=5, pady=5)

        # Статус ключа
        if is_file_tab:
            self.file_key_status = ttk.Label(settings_frame, text="", foreground="red")
            self.file_key_status.grid(row=1, column=2, sticky=tk.W, pady=(0, 10))
        else:
            self.text_key_status = ttk.Label(settings_frame, text="", foreground="red")
            self.text_key_status.grid(row=1, column=2, sticky=tk.W, pady=(0, 10))

        # IV
        ttk.Label(settings_frame, text="IV:").grid(row=2, column=0, sticky=tk.W, pady=5)

        iv_format_var = tk.StringVar(value="Hex")
        iv_combo = ttk.Combobox(settings_frame, textvariable=iv_format_var,
                               values=["Hex", "Текст"],  # Убрал "Случайный"
                               width=8, state="readonly")
        iv_combo.grid(row=2, column=1, sticky=tk.W, padx=(5, 10), pady=5)
        iv_combo.bind('<<ComboboxSelected>>', lambda e, tab=is_file_tab: self.on_format_changed(tab))

        iv_entry = ttk.Entry(settings_frame, textvariable=iv_var, width=60)
        iv_entry.grid(row=2, column=2, sticky=(tk.W, tk.E), padx=(0, 10), pady=5)

        # Кнопка случайного IV для текущей вкладки
        ttk.Button(settings_frame, text="Случайный IV",
                  command=lambda: self.generate_random_iv(is_file_tab)).grid(row=2, column=3, padx=5, pady=5)

        # Статус IV
        if is_file_tab:
            self.file_iv_status = ttk.Label(settings_frame, text="", foreground="red")
            self.file_iv_status.grid(row=3, column=2, sticky=tk.W, pady=(0, 10))
            # Сохраняем ссылки на виджеты файловой вкладки
            self.file_key_entry = key_entry
            self.file_iv_entry = iv_entry
            self.file_key_format = key_format_var
            self.file_iv_format = iv_format_var
        else:
            self.text_iv_status = ttk.Label(settings_frame, text="", foreground="red")
            self.text_iv_status.grid(row=3, column=2, sticky=tk.W, pady=(0, 10))
            # Сохраняем ссылки на виджеты текстовой вкладки
            self.text_key_entry = key_entry
            self.text_iv_entry = iv_entry
            self.text_key_format = key_format_var
            self.text_iv_format = iv_format_var

    def create_status_bar(self):
        """Создание строки состояния"""
        self.status_var = tk.StringVar(value="Введите ключ и IV")
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        ttk.Label(status_frame, textvariable=self.status_var,
                 relief=tk.SUNKEN, padding=(5, 5)).pack(fill=tk.X)

    def create_text_context_menu(self):
        """Создание контекстного меню для текстовых полей"""
        # Меню для входного текста
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

        # Привязка меню
        self.input_text.bind("<Button-3>", lambda e: self.show_context_menu(e, self.input_menu))
        self.output_text.bind("<Button-3>", lambda e: self.show_context_menu(e, self.output_menu))

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
            pass

    def paste_text(self, text_widget):
        """Вставить текст"""
        try:
            text = self.root.clipboard_get()
            text_widget.insert(tk.INSERT, text)
        except tk.TclError:
            pass

    def cut_text(self, text_widget):
        """Вырезать текст"""
        try:
            text = text_widget.get("sel.first", "sel.last")
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            text_widget.delete("sel.first", "sel.last")
        except tk.TclError:
            pass

    def select_all(self, text_widget):
        """Выделить весь текст"""
        text_widget.tag_add(tk.SEL, "1.0", tk.END)
        text_widget.mark_set(tk.INSERT, "1.0")
        text_widget.see(tk.INSERT)

    def on_format_changed(self, is_file_tab):
        """Обработчик изменения формата"""
        # Эта функция теперь простая, так как убрали "Случайный" из списка
        pass

    def validate_key(self, is_file_tab=False):
        """Валидация ключа"""
        if is_file_tab:
            key_text = self.file_key_var.get().strip()
            format_type = self.file_key_format.get()
            status_label = self.file_key_status
        else:
            key_text = self.text_key_var.get().strip()
            format_type = self.text_key_format.get()
            status_label = self.text_key_status

        if not key_text:
            status_label.config(text="Ключ не задан", foreground="red")
            self.key = b''
            self.update_status()
            return False

        try:
            if format_type == "Hex":
                clean_text = key_text.replace(' ', '')
                if not all(c in "0123456789ABCDEFabcdef" for c in clean_text):
                    raise ValueError("Неверный hex формат")
                key_bytes = bytes.fromhex(clean_text)
            else:
                key_bytes = key_text.encode('utf-8')

            if not (MIN_KEY_LEN <= len(key_bytes) <= MAX_KEY_LEN):
                raise ValueError(f"Длина должна быть {MIN_KEY_LEN}-{MAX_KEY_LEN} байт")

            self.key = key_bytes
            status_label.config(text=f"✓ {len(key_bytes)} байт ({len(key_bytes)*8} бит)",
                             foreground="green")
            self.update_status()
            return True

        except ValueError as e:
            status_label.config(text=f"Ошибка: {str(e)}", foreground="red")
            self.key = b''
            self.update_status()
            return False

    def validate_iv(self, is_file_tab=False):
        """Валидация IV"""
        if is_file_tab:
            iv_text = self.file_iv_var.get().strip()
            format_type = self.file_iv_format.get()
            status_label = self.file_iv_status
        else:
            iv_text = self.text_iv_var.get().strip()
            format_type = self.text_iv_format.get()
            status_label = self.text_iv_status

        if not iv_text:
            status_label.config(text="IV не задан", foreground="red")
            self.iv = b''
            self.update_status()
            return False

        try:
            if format_type == "Hex":
                clean_text = iv_text.replace(' ', '')
                if not all(c in "0123456789ABCDEFabcdef" for c in clean_text):
                    raise ValueError("Неверный hex формат")
                iv_bytes = bytes.fromhex(clean_text)
            else:
                iv_bytes = iv_text.encode('utf-8')

            if len(iv_bytes) > MAX_IV_LEN:
                raise ValueError(f"Длина не должна превышать {MAX_IV_LEN} байт")

            if len(iv_bytes) < MAX_IV_LEN:
                iv_bytes += b'\0' * (MAX_IV_LEN - len(iv_bytes))

            self.iv = iv_bytes
            status_label.config(text=f"✓ {len(iv_bytes)} байт ({len(iv_bytes)*8} бит)",
                              foreground="green")
            self.update_status()
            return True

        except ValueError as e:
            status_label.config(text=f"Ошибка: {str(e)}", foreground="red")
            self.iv = b''
            self.update_status()
            return False

    def update_status(self):
        """Обновление статусной строки"""
        if self.key and self.iv:
            key_hash = hashlib.sha256(self.key).hexdigest()[:8]
            iv_hash = hashlib.sha256(self.iv).hexdigest()[:8]
            self.status_var.set(f"✓ Готово! Ключ: {len(self.key)}B, IV: {len(self.iv)}B | Хеши: K:{key_hash}... IV:{iv_hash}...")
        else:
            self.status_var.set("Введите валидные ключ и IV")

    def encrypt_text(self):
        """Шифрование текста"""
        if not self.key or not self.iv:
            messagebox.showwarning("Ошибка", "Сначала задайте валидные ключ и IV")
            return

        plaintext = self.input_text.get("1.0", tk.END).strip()
        if not plaintext:
            messagebox.showwarning("Ошибка", "Введите текст для шифрования")
            return

        try:
            cipher = CustomSosemanuk(self.key, self.iv)
            ciphertext = cipher.encrypt_data(plaintext.encode('utf-8'))

            hex_text = ciphertext.hex()
            formatted_hex = ' '.join(hex_text[i:i+2] for i in range(0, len(hex_text), 2))

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", formatted_hex)

            self.status_var.set(f"✓ Текст зашифрован ({len(ciphertext)} байт)")

        except Exception as e:
            messagebox.showerror("Ошибка шифрования", str(e))
            self.status_var.set(f"✗ Ошибка: {str(e)}")

    def decrypt_text(self):
        """Расшифровка текста"""
        if not self.key or not self.iv:
            messagebox.showwarning("Ошибка", "Сначала задайте валидные ключ и IV")
            return

        hex_text = self.input_text.get("1.0", tk.END).strip().replace(' ', '').replace('\n', '')
        if not hex_text:
            messagebox.showwarning("Ошибка", "Введите hex для расшифровки")
            return

        try:
            ciphertext = bytes.fromhex(hex_text)
            cipher = CustomSosemanuk(self.key, self.iv)
            plaintext = cipher.decrypt_data(ciphertext)

            try:
                result = plaintext.decode('utf-8')
            except UnicodeDecodeError:
                result = f"[Бинарные данные, размер: {len(plaintext)} байт]\n"
                result += ' '.join(plaintext[i:i+1].hex() for i in range(min(len(plaintext), 50)))
                if len(plaintext) > 50:
                    result += "\n... (показано 50 байт)"

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", result)

            self.status_var.set(f"✓ Текст расшифрован ({len(plaintext)} байт)")

        except ValueError as e:
            messagebox.showerror("Ошибка", f"Неверный hex формат: {e}")
        except Exception as e:
            messagebox.showerror("Ошибка дешифрования", str(e))

    def generate_random_key(self, is_file_tab=False):
        """Генерация случайного ключа для указанной вкладки"""
        import secrets
        key_len = secrets.randbelow(MAX_KEY_LEN - MIN_KEY_LEN + 1) + MIN_KEY_LEN
        key_bytes = os.urandom(key_len)

        hex_key = key_bytes.hex()
        formatted_hex = ' '.join(hex_key[i:i+2] for i in range(0, len(hex_key), 2))

        if is_file_tab:
            self.file_key_format.set("Hex")
            self.file_key_var.set(formatted_hex)
            self.validate_key(is_file_tab=True)
        else:
            self.text_key_format.set("Hex")
            self.text_key_var.set(formatted_hex)
            self.validate_key(is_file_tab=False)

    def generate_random_iv(self, is_file_tab=False):
        """Генерация случайного IV для указанной вкладки"""
        iv_bytes = os.urandom(MAX_IV_LEN)
        hex_iv = iv_bytes.hex()
        formatted_hex = ' '.join(hex_iv[i:i+2] for i in range(0, len(hex_iv), 2))

        if is_file_tab:
            self.file_iv_format.set("Hex")
            self.file_iv_var.set(formatted_hex)
            self.validate_iv(is_file_tab=True)
        else:
            self.text_iv_format.set("Hex")
            self.text_iv_var.set(formatted_hex)
            self.validate_iv(is_file_tab=False)

    def clear_text_fields(self):
        """Очистка полей ввода/вывода"""
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.status_var.set("Текстовые поля очищены")

    # ============= НОВЫЕ МЕТОДЫ ДЛЯ РАБОТЫ С ФАЙЛАМИ =============

    def select_file(self):
        """Выбор файла для шифрования/расшифрования"""
        file_path = filedialog.askopenfilename(
            title="Выберите файл",
            filetypes=[
                ("Все файлы", "*.*"),
                ("Архивы", "*.zip *.7z *.rar *.tar *.gz"),
                ("Документы", "*.docx *.doc *.xlsx *.xls *.pptx *.ppt *.pdf"),
                ("Изображения", "*.jpg *.jpeg *.png *.bmp *.gif"),
                ("Текстовые файлы", "*.txt *.csv *.xml *.json")
            ]
        )

        if file_path:
            self.file_path_var.set(file_path)
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            self.file_info_label.config(
                text=f"Файл: {file_name} | Размер: {self.format_file_size(file_size)}"
            )
            self.operation_status_var.set(f"Выбран файл: {file_name}")

    def format_file_size(self, size_bytes):
        """Форматирование размера файла для отображения"""
        for unit in ['Б', 'КБ', 'МБ', 'ГБ']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} ТБ"

    def encrypt_file(self):
        """Шифрование файла"""
        if not self.validate_encryption_params():
            return

        input_file = self.file_path_var.get()
        if not input_file or not os.path.exists(input_file):
            messagebox.showwarning("Ошибка", "Выберите файл для шифрования")
            return

        # Диалог выбора места сохранения
        output_file = filedialog.asksaveasfilename(
            title="Сохранить зашифрованный файл как",
            defaultextension=".enc",
            filetypes=[("Зашифрованные файлы", "*.enc"), ("Все файлы", "*.*")]
        )

        if not output_file:
            return  # Пользователь отменил

        # Запуск в отдельном потоке
        thread = threading.Thread(
            target=self.process_file,
            args=(input_file, output_file, 'encrypt')
        )
        thread.daemon = True
        thread.start()

    def decrypt_file(self):
        """Расшифрование файла"""
        if not self.validate_encryption_params():
            return

        input_file = self.file_path_var.get()
        if not input_file or not os.path.exists(input_file):
            messagebox.showwarning("Ошибка", "Выберите файл для расшифрования")
            return

        # Определяем исходное расширение (если есть)
        input_path = Path(input_file)
        if input_path.suffix == '.enc':
            # Пытаемся восстановить оригинальное имя
            default_name = input_path.stem
        else:
            default_name = input_path.name + ".decrypted"

        # Диалог выбора места сохранения
        output_file = filedialog.asksaveasfilename(
            title="Сохранить расшифрованный файл как",
            initialfile=default_name,
            filetypes=[("Все файлы", "*.*")]
        )

        if not output_file:
            return

        # Запуск в отдельном потоке
        thread = threading.Thread(
            target=self.process_file,
            args=(input_file, output_file, 'decrypt')
        )
        thread.daemon = True
        thread.start()

    def validate_encryption_params(self):
        """Проверка параметров шифрования"""
        if not self.key or not self.iv:
            messagebox.showwarning("Ошибка", "Сначала задайте валидные ключ и IV")
            return False
        return True

    def process_file(self, input_path, output_path, mode):
        """Обработка файла (шифрование/расшифрование)"""
        try:
            # Обновляем статус
            self.root.after(0, self.update_operation_status,
                          f"{'Шифрование' if mode == 'encrypt' else 'Расшифрование'}...")
            self.root.after(0, self.progress_var.set, 0)

            # Создаем экземпляр шифра
            cipher = CustomSosemanuk(self.key, self.iv)

            # Размер блока для обработки (1 МБ)
            BLOCK_SIZE = 1024 * 1024
            total_size = os.path.getsize(input_path)
            processed = 0
            start_time = time.time()

            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                while True:
                    # Чтение блока
                    block = infile.read(BLOCK_SIZE)
                    if not block:
                        break

                    # Обработка блока
                    if mode == 'encrypt':
                        processed_block = cipher.encrypt_data(block)
                    else:  # decrypt
                        processed_block = cipher.decrypt_data(block)

                    # Запись результата
                    outfile.write(processed_block)

                    # Обновление прогресса
                    processed += len(block)
                    progress = (processed / total_size) * 100
                    self.root.after(0, self.progress_var.set, progress)

                    # Обновление статуса
                    elapsed = time.time() - start_time
                    speed = processed / elapsed if elapsed > 0 else 0
                    remaining = (total_size - processed) / speed if speed > 0 else 0

                    status_msg = (
                        f"{'Шифрование' if mode == 'encrypt' else 'Расшифрование'}: "
                        f"{progress:.1f}% ({self.format_file_size(processed)}/{self.format_file_size(total_size)})"
                    )
                    self.root.after(0, self.update_operation_status, status_msg)

            # Завершение
            elapsed_total = time.time() - start_time
            self.root.after(0, self.on_file_processed,
                          f"Файл успешно {'зашифрован' if mode == 'encrypt' else 'расшифрован'}!\n"
                          f"Размер: {self.format_file_size(total_size)}\n"
                          f"Время: {elapsed_total:.2f} сек\n"
                          f"Сохранен как: {os.path.basename(output_path)}")

        except Exception as e:
            self.root.after(0, self.on_file_error, str(e))
        finally:
            self.root.after(0, self.reset_file_ui)

    def update_operation_status(self, message):
        """Обновление статуса файловой операции"""
        self.operation_status_var.set(message)

    def on_file_processed(self, message):
        """Обработка успешного завершения операции"""
        messagebox.showinfo("Успех", message)
        self.operation_status_var.set("Операция завершена успешно")

    def on_file_error(self, error_message):
        """Обработка ошибки при работе с файлом"""
        messagebox.showerror("Ошибка", f"Ошибка при обработке файла:\n{error_message}")
        self.operation_status_var.set(f"Ошибка: {error_message}")

    def reset_file_ui(self):
        """Сброс UI после завершения операции"""
        self.progress_var.set(0)

    def clear_file_fields(self):
        """Очистка полей ввода файлов"""
        self.file_path_var.set("")
        self.file_info_label.config(text="Файл не выбран")
        self.operation_status_var.set("")
        self.progress_var.set(0)


def main():
    """Главная функция"""
    root = tk.Tk()
    app = SosemanukGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()