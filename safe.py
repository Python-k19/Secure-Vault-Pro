import sys
import os
import json
import secrets
import string
import tempfile
import time
from pathlib import Path
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                               QTreeWidget, QTreeWidgetItem, QMessageBox, QFrame,
                               QAbstractItemView, QInputDialog, QMenu, QHeaderView, 
                               QFileIconProvider, QToolButton, QFileDialog,
                               QProgressBar)
from PySide6.QtCore import Qt, QMimeData, QUrl, QTimer, QPoint, QSize
from PySide6.QtGui import (QFont, QDragEnterEvent, QDropEvent, QDrag, QAction, 
                            QColor, QBrush, QDesktopServices)

STYLESHEET = """
QMainWindow, QWidget { background-color: #121212; color: #e0e0e0; }
QLabel { font-family: 'Segoe UI', sans-serif; }
QLineEdit { 
    background-color: #1e1e1e; border: 1px solid #333; 
    padding: 12px; border-radius: 8px; font-size: 16px; color: white;
}
QLineEdit:focus { border: 1px solid #bb86fc; }
QLineEdit#passwordDisplay { 
    font-family: 'Consolas', monospace;
    font-size: 13px;
    padding: 10px;
    background-color: #1a0f1f;
    border: 1px solid #bb86fc;
    color: #bb86fc;
}
QPushButton {
    background-color: #bb86fc; color: #000; border: none;
    padding: 10px 16px; border-radius: 6px; font-weight: 600; font-size: 12px;
}
QPushButton:hover { background-color: #9965f4; }
QPushButton#closeBtn { background-color: #cf6679; color: white; }
QPushButton#closeBtn:hover { background-color: #b00020; }
QPushButton#deleteBtn { background-color: #ff5252; color: white; }
QPushButton#deleteBtn:hover { background-color: #d32f2f; }
QPushButton#folderBtn { background-color: #03dac6; color: #000; }
QPushButton#folderBtn:hover { background-color: #018c7d; }
QPushButton#extractBtn { background-color: #ffab40; color: #000; }
QPushButton#extractBtn:hover { background-color: #ff8f00; }
QPushButton#copyBtn { background-color: #444; color: #fff; padding: 8px 12px; }
QPushButton#copyBtn:hover { background-color: #555; }
QTreeWidget {
    background-color: #1a1a1a; border: 1px solid #333;
    border-radius: 8px; padding: 8px; font-size: 13px; outline: none;
    alternate-background-color: #1e1e1e;
}
QTreeWidget::item { padding: 10px 8px; border-radius: 4px; min-height: 28px; }
QTreeWidget::item:selected { background-color: #2d2d2d; color: #bb86fc; }
QTreeWidget::item:hover { background-color: #252525; }
QTreeWidget::branch { background: transparent; }
QHeaderView::section {
    background-color: #161616; color: #888; border: none;
    padding: 10px 8px; font-weight: 600;
}
#dropZone {
    border: 2px dashed #333; border-radius: 12px;
    background-color: #161616; min-height: 100px;
    font-size: 14px; color: #666;
}
#dropZone[dragOver="true"] { 
    border-color: #bb86fc; background-color: #1f1a24; color: #bb86fc; 
}
QMenu {
    background-color: #1e1e1e; border: 1px solid #333;
    border-radius: 6px; padding: 4px;
}
QMenu::item { padding: 8px 20px; border-radius: 4px; }
QMenu::item:selected { background-color: #bb86fc; color: #000; }
#warningLabel {
    color: #ff5252; font-weight: 700; font-size: 13px;
    padding: 8px; background-color: #2d0a0a; border-radius: 6px;
    border: 1px solid #ff5252;
}
#attemptsLabel {
    color: #ffab40; font-size: 12px; font-weight: 600;
}
#attemptsLabel.critical {
    color: #ff5252;
}
"""

ROLE_TYPE = Qt.UserRole
TYPE_FOLDER = "folder"
TYPE_FILE = "file"
TYPE_PLACEHOLDER = "placeholder"

MAX_ATTEMPTS = 10  # Количество попыток до самоуничтожения


class CryptoEngine:
    """
    Архитектура crypto-shredding:
    - Master Key (случайный) — шифрует файлы
    - KEK (Key Encryption Key) — шифрует Master Key, выводится из пароля
    - При самоуничтожении удаляется KEK + Master Key → файлы невосстановимы
    """
    
    def __init__(self, vault_path: str):
        self.vault_path = Path(vault_path)
        self.vault_path.mkdir(exist_ok=True)
        self.index_file = self.vault_path / ".vault_meta.enc"
        self.salt_file = self.vault_path / ".salt"
        self.master_key_file = self.vault_path / ".master_key.enc"
        self.attempts_file = self.vault_path / ".vault_attempts"
        self.kek = None        # Key Encryption Key (из пароля)
        self.master_key = None  # Master key для шифрования файлов
        
    def is_new_vault(self) -> bool:
        return not self.salt_file.exists()
    
    def is_destroyed(self) -> bool:
        """Проверяет, был ли сейф самоуничтожен"""
        if not self.salt_file.exists():
            return False
        return not self.master_key_file.exists()
    
    @staticmethod
    def generate_strong_password(length: int = 50) -> str:
        """Генерирует криптографически стойкий пароль"""
        # Все группы символов обязательно присутствуют
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\₴₽€£¥©®™§¶†‡"
        
        # Гарантируем наличие каждой группы
        password_chars = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(symbols),
        ]
        
        # Остальные символы — случайная смесь
        all_chars = lowercase + uppercase + digits + symbols
        for _ in range(length - 4):
            password_chars.append(secrets.choice(all_chars))
        
        # Перемешиваем
        # secrets не имеет shuffle, используем Fisher-Yates вручную
        for i in range(len(password_chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_chars[i], password_chars[j] = password_chars[j], password_chars[i]
        
        return ''.join(password_chars)
    
    def _get_or_create_salt(self) -> bytes:
        if self.salt_file.exists():
            return self.salt_file.read_bytes()
        salt = secrets.token_bytes(16)
        self.salt_file.write_bytes(salt)
        return salt
    
    def _derive_kek(self, password: str) -> bytes:
        """Выводит KEK из пароля через Argon2id"""
        salt = self._get_or_create_salt()
        return hash_secret_raw(
            secret=password.encode(), salt=salt, 
            time_cost=4, memory_cost=131072,  # Увеличено для замедления брутфорса
            parallelism=4, hash_len=32, type=Type.ID
        )
    
    def create_vault(self, password: str):
        """Создаёт новый сейф с master-ключом"""
        # Случайный master-ключ (криптографически)
        self.master_key = secrets.token_bytes(32)
        self.kek = self._derive_kek(password)
        
        # Шифруем master-ключ через KEK
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self.kek)
        encrypted_master = aesgcm.encrypt(nonce, self.master_key, b"vault-master-key-v1")
        
        # Сохраняем с версией для совместимости
        master_data = b"VK1" + nonce + encrypted_master
        self.master_key_file.write_bytes(master_data)
        
        # Сбрасываем счётчик попыток
        self._save_attempts(0)
    
    def unlock(self, password: str) -> bool:
        """
        Пытается открыть сейф.
        Возвращает True при успехе, False при неверном пароле.
        Бросает DestroyedError при самоуничтожении.
        """
        attempts = self._load_attempts()
        
        if attempts >= MAX_ATTEMPTS:
            raise DestroyedError("Сейф самоуничтожен")
        
        if self.is_destroyed():
            raise DestroyedError("Сейф был самоуничтожен ранее")
        
        kek = self._derive_kek(password)
        
        try:
            master_data = self.master_key_file.read_bytes()
            if not master_data.startswith(b"VK1"):
                raise ValueError("Неизвестный формат master key")
            
            nonce = master_data[3:15]
            encrypted_master = master_data[15:]
            
            aesgcm = AESGCM(kek)
            self.master_key = aesgcm.decrypt(nonce, encrypted_master, b"vault-master-key-v1")
            self.kek = kek
            
            # Успех — сбрасываем счётчик
            self._save_attempts(0)
            return True
            
        except Exception:
            # Неверный пароль — увеличиваем счётчик
            new_attempts = attempts + 1
            self._save_attempts(new_attempts)
            
            if new_attempts >= MAX_ATTEMPTS:
                self.self_destruct()
                raise DestroyedError(f"Превышено {MAX_ATTEMPTS} попыток. Сейф самоуничтожен.")
            
            return False
    
    def _save_attempts(self, count: int):
        """Сохраняет счётчик с tamper-evident защитой"""
        data = {
            "count": count,
            "max": MAX_ATTEMPTS,
            "timestamp": time.time(),
            # HMAC для защиты от подделки
            "hmac": self._attempts_hmac(count)
        }
        self.attempts_file.write_bytes(json.dumps(data).encode())
    
    def _load_attempts(self) -> int:
        """Загружает счётчик с проверкой целостности"""
        if not self.attempts_file.exists():
            return 0
        try:
            data = json.loads(self.attempts_file.read_bytes().decode())
            count = data.get("count", 0)
            expected_hmac = data.get("hmac", "")
            
            # Проверка целостности (если salt существует)
            if self.salt_file.exists():
                if self._attempts_hmac(count) != expected_hmac:
                    # Подделка — считаем, что было MAX_ATTEMPTS
                    return MAX_ATTEMPTS
            return count
        except Exception:
            return MAX_ATTEMPTS  # При ошибке — самоуничтожение
    
    def _attempts_hmac(self, count: int) -> str:
        """HMAC на основе соли (не пароля) для tamper-evident защиты"""
        if not self.salt_file.exists():
            return ""
        salt = self.salt_file.read_bytes()
        # Детерминированный хэш от счётчика + соли
        h = hash_secret_raw(
            secret=f"attempts:{count}:{MAX_ATTEMPTS}".encode(),
            salt=salt,
            time_cost=1, memory_cost=8192, parallelism=1,
            hash_len=16, type=Type.ID
        )
        return h.hex()
    
    def self_destruct(self):
        """
        Криптографическое самоуничтожение.
        Удаляет master_key + salt → файлы невозможно расшифровать НИКОГДА.
        """
        # Перезаписываем master_key случайными данными несколько раз
        if self.master_key_file.exists():
            for _ in range(7):
                self.master_key_file.write_bytes(secrets.token_bytes(64))
            try:
                self.master_key_file.unlink()
            except Exception:
                pass
        
        # Удаляем соль (без неё нельзя вывести KEK)
        if self.salt_file.exists():
            for _ in range(7):
                self.salt_file.write_bytes(secrets.token_bytes(64))
            try:
                self.salt_file.unlink()
            except Exception:
                pass
        
        # Помечаем индекс как уничтоженный
        if self.index_file.exists():
            self.index_file.write_bytes(b"DESTROYED")
        
        # Очищаем память
        self.master_key = None
        self.kek = None
    
    def encrypt(self, data: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self.master_key)
        ct = aesgcm.encrypt(nonce, data, None)
        return nonce + ct
    
    def decrypt(self, token: bytes) -> bytes:
        nonce, ct = token[:12], token[12:]
        aesgcm = AESGCM(self.master_key)
        return aesgcm.decrypt(nonce, ct, None)
    
    def save_index(self, index: dict):
        enc = self.encrypt(json.dumps(index).encode())
        self.index_file.write_bytes(enc)
            
    def load_index(self) -> dict:
        if not self.index_file.exists():
            return {"items": {}}
        try:
            dec = self.decrypt(self.index_file.read_bytes())
            return json.loads(dec.decode())
        except Exception:
            raise ValueError("Неверный пароль или поврежденный индекс")
    
    def delete_files_recursive(self, node_dict):
        for name, info in node_dict.items():
            if isinstance(info, dict):
                if info.get("type") == TYPE_FILE and "path" in info:
                    try:
                        file_path = Path(info["path"])
                        if file_path.exists():
                            file_path.unlink()
                    except Exception as e:
                        print(f"Не удалось удалить файл {info.get('path')}: {e}")
                elif info.get("type") == TYPE_FOLDER and "children" in info:
                    self.delete_files_recursive(info["children"])
    
    def get_remaining_attempts(self) -> int:
        """Возвращает количество оставшихся попыток"""
        if not self.salt_file.exists():
            return MAX_ATTEMPTS
        return MAX_ATTEMPTS - self._load_attempts()


class DestroyedError(Exception):
    """Сейф самоуничтожен"""
    pass


class DraggableTreeWidget(QTreeWidget):
    def __init__(self, crypto_engine, get_index_func, parent=None):
        super().__init__(parent)
        self.crypto = crypto_engine
        self.get_index = get_index_func
        self.temp_dirs = []
        self.view_temp_dirs = []
        self.icon_provider = QFileIconProvider()
        self._highlighted_item = None
        
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)
        self.setAnimated(True)
        self.setItemsExpandable(True)
        self.setExpandsOnDoubleClick(False)
        self.setIndentation(24)
        self.setRootIsDecorated(True)
        
        self.setHeaderLabels(["Имя", "Тип", "Размер", "Действия"])
        self.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.setColumnWidth(3, 110)
        
        self.doubleClicked.connect(self.on_item_double_clicked)
        self.itemExpanded.connect(self._on_item_expanded)
        self.itemCollapsed.connect(self._on_item_collapsed)
        
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()
    
    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            pos = event.position().toPoint() if hasattr(event, 'position') else event.pos()
            item = self.itemAt(pos)
            
            if self._highlighted_item and self._highlighted_item != item:
                self._reset_highlight(self._highlighted_item)
                self._highlighted_item = None
            
            if item and item.data(0, ROLE_TYPE) == TYPE_FOLDER:
                item.setBackground(0, QBrush(QColor("#2d1b3d")))
                for i in range(item.childCount()):
                    item.child(i).setBackground(0, QBrush(QColor("#2d1b3d")))
                self._highlighted_item = item
                event.acceptProposedAction()
            elif item and item.data(0, ROLE_TYPE) == TYPE_PLACEHOLDER:
                parent = item.parent()
                if parent and parent.data(0, ROLE_TYPE) == TYPE_FOLDER:
                    parent.setBackground(0, QBrush(QColor("#2d1b3d")))
                    for i in range(parent.childCount()):
                        parent.child(i).setBackground(0, QBrush(QColor("#2d1b3d")))
                    self._highlighted_item = parent
                    event.acceptProposedAction()
                else:
                    event.acceptProposedAction()
            else:
                event.acceptProposedAction()
        else:
            event.ignore()
    
    def dragLeaveEvent(self, event):
        if self._highlighted_item:
            self._reset_highlight(self._highlighted_item)
            self._highlighted_item = None
        super().dragLeaveEvent(event)
    
    def _reset_highlight(self, item):
        if item:
            item.setBackground(0, QBrush())
            for i in range(item.childCount()):
                item.child(i).setBackground(0, QBrush())
    
    def dropEvent(self, event: QDropEvent):
        if event.mimeData().hasUrls():
            pos = event.position().toPoint() if hasattr(event, 'position') else event.pos()
            item = self.itemAt(pos)
            
            if item and item.data(0, ROLE_TYPE) == TYPE_PLACEHOLDER:
                item = item.parent()
            
            target_path = []
            if item and item.data(0, ROLE_TYPE) == TYPE_FOLDER:
                current = item
                while current:
                    if current.data(0, ROLE_TYPE) != TYPE_PLACEHOLDER:
                        target_path.insert(0, current.text(0))
                    current = current.parent()
                target_dict = self._get_folder_children(item)
                target_name = item.text(0)
            else:
                target_dict = self.parent().window().current_index.setdefault("items", {})
                target_name = "корень сейфа"
            
            added = 0
            for url in event.mimeData().urls():
                path = Path(url.toLocalFile())
                try:
                    if path.is_file():
                        self.parent().window()._add_file_to_vault(path, target_dict)
                        added += 1
                    elif path.is_dir():
                        self.parent().window()._add_folder_to_vault(path, target_dict)
                        added += 1
                except Exception as e:
                    QMessageBox.warning(self, "Ошибка", f"Не удалось добавить {path.name}:\n{e}")
            
            if self._highlighted_item:
                self._reset_highlight(self._highlighted_item)
                self._highlighted_item = None
            
            if added > 0:
                self.parent().window()._refresh_tree()
                if target_path:
                    self._expand_path(target_path)
                QMessageBox.information(self, "Готово", 
                                        f"Добавлено {added} элемент(ов) в '{target_name}'")
            
            event.acceptProposedAction()
        else:
            event.ignore()
    
    def _expand_path(self, path_parts):
        current_items = [self.topLevelItem(i) for i in range(self.topLevelItemCount())]
        found_item = None
        
        for part in path_parts:
            found_item = None
            for item in current_items:
                if item.text(0) == part and item.data(0, ROLE_TYPE) != TYPE_PLACEHOLDER:
                    found_item = item
                    break
            
            if found_item:
                found_item.setExpanded(True)
                self._update_button_text(found_item)
                current_items = [found_item.child(i) for i in range(found_item.childCount())
                                if found_item.child(i).data(0, ROLE_TYPE) != TYPE_PLACEHOLDER]
            else:
                break
        
        if found_item:
            self.scrollToItem(found_item)
    
    def _get_folder_children(self, item) -> dict:
        path_parts = []
        current = item
        while current:
            if current.data(0, ROLE_TYPE) != TYPE_PLACEHOLDER:
                path_parts.insert(0, current.text(0))
            current = current.parent()
        
        index = self.parent().window().current_index
        node = index.setdefault("items", {})
        
        for part in path_parts:
            if part in node and isinstance(node[part], dict):
                folder_data = node[part]
                if folder_data.get("type") == TYPE_FOLDER:
                    node = folder_data.setdefault("children", {})
                else:
                    return node
            else:
                return node
        return node
    
    def on_item_double_clicked(self, index):
        item = self.itemFromIndex(index)
        if not item:
            return
        if item.data(0, ROLE_TYPE) == TYPE_PLACEHOLDER:
            return
        if item.data(0, ROLE_TYPE) == TYPE_FOLDER:
            item.setExpanded(not item.isExpanded())
            self._update_button_text(item)
            return
        if item.data(0, ROLE_TYPE) == TYPE_FILE:
            self.view_file(item)
    
    def view_file(self, item):
        index = self.get_index()
        path_info = self._get_file_info_from_item(item, index)
        
        if not path_info or "path" not in path_info:
            QMessageBox.warning(self, "Ошибка", "Информация о файле не найдена")
            return
        
        enc_path = Path(path_info["path"])
        if not enc_path.exists():
            QMessageBox.warning(self, "Ошибка", "Зашифрованный файл не найден на диске")
            return
        
        try:
            temp_dir = tempfile.TemporaryDirectory(prefix="vault_view_")
            self.view_temp_dirs.append(temp_dir)
            
            temp_path = Path(temp_dir.name) / item.text(0)
            enc_data = enc_path.read_bytes()
            dec_data = self.crypto.decrypt(enc_data)
            temp_path.write_bytes(dec_data)
            
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(temp_path)))
        except Exception as e:
            QMessageBox.critical(self, "Ошибка просмотра", f"Не удалось открыть файл:\n{e}")
    
    def _on_item_expanded(self, item):
        self._update_button_text(item)
    
    def _on_item_collapsed(self, item):
        self._update_button_text(item)
    
    def _update_button_text(self, item):
        if item.data(0, ROLE_TYPE) == TYPE_FOLDER:
            btn = self.itemWidget(item, 3)
            if btn:
                if item.isExpanded():
                    btn.setText("Закрыть")
                    btn.setStyleSheet("""
                        QToolButton {
                            background: #2d1b3d;
                            border: 1px solid #bb86fc;
                            border-radius: 4px;
                            padding: 4px 10px;
                            color: #bb86fc;
                            font-weight: 600;
                        }
                        QToolButton:hover { background: #3d2b4d; }
                    """)
                else:
                    btn.setText("Открыть")
                    btn.setStyleSheet("""
                        QToolButton {
                            background: #1e1e1e;
                            border: 1px solid #333;
                            border-radius: 4px;
                            padding: 4px 10px;
                            color: #bb86fc;
                            font-weight: 500;
                        }
                        QToolButton:hover {
                            background: #2d2d2d;
                            border-color: #bb86fc;
                        }
                    """)
    
    def startDrag(self, supportedActions):
        items = [it for it in self.selectedItems() 
                if it.data(0, ROLE_TYPE) in (TYPE_FILE, TYPE_FOLDER)]
        
        if not items:
            return
        
        temp_dir = tempfile.TemporaryDirectory(prefix="vault_export_")
        self.temp_dirs.append(temp_dir)
        
        mime_data = QMimeData()
        urls = []
        index = self.get_index()
        
        for item in items:
            if item.data(0, ROLE_TYPE) == TYPE_FILE:
                file_info = self._get_file_info_from_item(item, index)
                if file_info and "path" in file_info:
                    enc_path = Path(file_info["path"])
                    if enc_path.exists():
                        try:
                            temp_path = Path(temp_dir.name) / item.text(0)
                            enc_data = enc_path.read_bytes()
                            dec_data = self.crypto.decrypt(enc_data)
                            temp_path.write_bytes(dec_data)
                            urls.append(QUrl.fromLocalFile(str(temp_path)))
                        except Exception as e:
                            print(f"Ошибка расшифровки {item.text(0)}: {e}")
            
            elif item.data(0, ROLE_TYPE) == TYPE_FOLDER:
                folder_name = item.text(0)
                folder_temp = Path(temp_dir.name) / folder_name
                folder_temp.mkdir(exist_ok=True)
                
                folder_children = self._get_folder_node_from_item(item, index)
                if folder_children is not None:
                    try:
                        self._export_folder_recursive_index(folder_children, folder_temp)
                        urls.append(QUrl.fromLocalFile(str(folder_temp)))
                    except Exception as e:
                        print(f"Ошибка экспорта папки {folder_name}: {e}")
        
        if not urls:
            return
        
        mime_data.setUrls(urls)
        drag = QDrag(self)
        drag.setMimeData(mime_data)
        drag.exec(Qt.CopyAction)
        
        QTimer.singleShot(300000, lambda td=temp_dir: self._cleanup_temp(td))
    
    def _get_file_info_from_item(self, item, index):
        path_parts = []
        current = item
        while current:
            if current.data(0, ROLE_TYPE) != TYPE_PLACEHOLDER:
                path_parts.insert(0, current.text(0))
            current = current.parent()
        
        node = index.get("items", {})
        for part in path_parts:
            if part in node:
                node = node[part]
            else:
                return None
        return node if isinstance(node, dict) and node.get("type") == TYPE_FILE else None
    
    def _get_folder_node_from_item(self, item, index):
        path_parts = []
        current = item
        while current:
            if current.data(0, ROLE_TYPE) != TYPE_PLACEHOLDER:
                path_parts.insert(0, current.text(0))
            current = current.parent()
        
        node = index.get("items", {})
        for part in path_parts:
            if part in node and isinstance(node[part], dict):
                node = node[part]
            else:
                return None
        
        if isinstance(node, dict) and node.get("type") == TYPE_FOLDER:
            return node.get("children", {})
        return None
    
    def _export_folder_recursive_index(self, children_dict, dest_dir: Path):
        for name, info in children_dict.items():
            if isinstance(info, dict):
                if info.get("type") == TYPE_FILE and "path" in info:
                    enc_path = Path(info["path"])
                    if enc_path.exists():
                        try:
                            temp_path = dest_dir / name
                            enc_data = enc_path.read_bytes()
                            dec_data = self.crypto.decrypt(enc_data)
                            temp_path.write_bytes(dec_data)
                        except Exception as e:
                            print(f"Ошибка расшифровки {name}: {e}")
                
                elif info.get("type") == TYPE_FOLDER:
                    sub_dir = dest_dir / name
                    sub_dir.mkdir(exist_ok=True)
                    self._export_folder_recursive_index(info.get("children", {}), sub_dir)
        
    def _cleanup_temp(self, temp_dir):
        try:
            if temp_dir in self.temp_dirs:
                self.temp_dirs.remove(temp_dir)
            temp_dir.cleanup()
        except PermissionError:
            QTimer.singleShot(60000, lambda: self._cleanup_temp(temp_dir))
        except Exception:
            pass
    
    def show_context_menu(self, position: QPoint):
        item = self.itemAt(position)
        menu = QMenu(self)
        
        if item and item.data(0, ROLE_TYPE) == TYPE_PLACEHOLDER:
            item = item.parent()
        
        if item:
            item_type = item.data(0, ROLE_TYPE)
            
            if item_type == TYPE_FOLDER:
                new_subfolder_action = QAction("📁 Создать подпапку", self)
                new_subfolder_action.triggered.connect(lambda: self.create_subfolder(item))
                menu.addAction(new_subfolder_action)
                menu.addSeparator()
            
            if item_type == TYPE_FILE:
                view_action = QAction("👁 Открыть для просмотра", self)
                view_action.triggered.connect(lambda: self.view_file(item))
                menu.addAction(view_action)
                
                export_action = QAction("📤 Экспортировать...", self)
                export_action.triggered.connect(lambda: self.export_file(item))
                menu.addAction(export_action)
                menu.addSeparator()
            
            delete_action = QAction("🗑 Удалить", self)
            delete_action.triggered.connect(lambda: self.delete_item(item))
            menu.addAction(delete_action)
            
            rename_action = QAction("✏ Переименовать", self)
            rename_action.triggered.connect(lambda: self.rename_item(item))
            menu.addAction(rename_action)
        else:
            new_folder_action = QAction("📁 Создать папку здесь", self)
            new_folder_action.triggered.connect(lambda: self.parent().window().create_folder())
            menu.addAction(new_folder_action)
        
        menu.exec(self.mapToGlobal(position))
    
    def create_subfolder(self, parent_item):
        folder_name, ok = QInputDialog.getText(self, "Новая подпапка", "Имя подпапки:")
        if ok and folder_name:
            target_dict = self._get_folder_children(parent_item)
            if folder_name in target_dict:
                QMessageBox.warning(self, "Ошибка", "Папка с таким именем уже существует")
                return
            target_dict[folder_name] = {"type": TYPE_FOLDER, "children": {}}
            self.parent().window()._refresh_tree()
        
    def export_file(self, item):
        name = item.text(0)
        index = self.get_index()
        path_info = self._get_file_info_from_item(item, index)
        
        if not path_info or "path" not in path_info:
            return
        enc_path = Path(path_info["path"])
        if not enc_path.exists():
            return
        save_path, _ = QFileDialog.getSaveFileName(self, "Сохранить файл", name)
        if save_path:
            try:
                enc_data = enc_path.read_bytes()
                dec_data = self.crypto.decrypt(enc_data)
                Path(save_path).write_bytes(dec_data)
                QMessageBox.information(self, "Успех", f"Файл сохранен: {save_path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось экспортировать:\n{e}")
                
    def delete_item(self, item):
        name = item.text(0)
        item_type = item.data(0, ROLE_TYPE)
        
        reply = QMessageBox.question(
            self, "Подтверждение удаления",
            f"Удалить {item_type} '{name}'?\n{'Все содержимое папки будет удалено.' if item_type == TYPE_FOLDER else ''}",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            path_parts = []
            current = item
            while current:
                if current.data(0, ROLE_TYPE) != TYPE_PLACEHOLDER:
                    path_parts.insert(0, current.text(0))
                current = current.parent()
            
            index = self.parent().window().current_index
            node = index.get("items", {})
            node_to_delete = None
            
            for part in path_parts:
                if part in node:
                    node_to_delete = node[part]
                    node = node[part] if isinstance(node[part], dict) else {}
                else:
                    break
            
            if node_to_delete and isinstance(node_to_delete, dict):
                if node_to_delete.get("type") == TYPE_FILE:
                    self.crypto.delete_files_recursive({"_": node_to_delete})
                elif node_to_delete.get("type") == TYPE_FOLDER:
                    self.crypto.delete_files_recursive(node_to_delete.get("children", {}))
            
            parent = item.parent()
            if parent:
                parent.removeChild(item)
            else:
                self.takeTopLevelItem(self.indexOfTopLevelItem(item))
            
            self.parent().window().on_tree_changed()
            
    def rename_item(self, item):
        old_name = item.text(0)
        new_name, ok = QInputDialog.getText(self, "Переименовать", "Новое имя:", text=old_name)
        if ok and new_name and new_name != old_name:
            item.setText(0, new_name)
            self.parent().window().on_tree_changed()


class VaultApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Vault Pro 🔒 Anti-BruteForce")
        self.resize(800, 850)
        self.crypto = CryptoEngine("./secure_vault_data")
        self.current_index = {"items": {}}
        self.icon_provider = QFileIconProvider()
        self._last_failed_attempt = 0  # Для экспоненциальной задержки
        
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(15)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # --- ЭКРАН ВХОДА ---
        self.login_frame = QFrame()
        lf_layout = QVBoxLayout(self.login_frame)
        title = QLabel("🔐 SECURE VAULT")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 28px; font-weight: 800; color: #bb86fc; margin-bottom: 20px;")
        
        subtitle = QLabel("🛡 Защита от брутфорса активна • Crypto-shredding")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #888; font-size: 12px; margin-bottom: 15px;")
        
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.Password)
        self.pwd_input.setPlaceholderText("Введите мастер-пароль...")
        self.pwd_input.returnPressed.connect(self.unlock)
        
        self.pwd_confirm_input = QLineEdit()
        self.pwd_confirm_input.setEchoMode(QLineEdit.Password)
        self.pwd_confirm_input.setPlaceholderText("Подтвердите пароль...")
        self.pwd_confirm_input.returnPressed.connect(self.unlock)
        
        # Генератор пароля (только для нового сейфа)
        self.password_gen_frame = QFrame()
        pg_layout = QVBoxLayout(self.password_gen_frame)
        pg_layout.setSpacing(8)
        
        gen_label = QLabel("🎲 Сгенерированный криптографически стойкий пароль (50 символов):")
        gen_label.setStyleSheet("color: #bb86fc; font-size: 12px; font-weight: 600;")
        
        self.generated_pwd_display = QLineEdit()
        self.generated_pwd_display.setObjectName("passwordDisplay")
        self.generated_pwd_display.setReadOnly(True)
        self.generated_pwd_display.setText(CryptoEngine.generate_strong_password(50))
        
        copy_use_btns = QHBoxLayout()
        copy_btn = QPushButton("📋 Скопировать")
        copy_btn.setObjectName("copyBtn")
        copy_btn.clicked.connect(self.copy_generated_password)
        
        regen_btn = QPushButton("🔄 Другой")
        regen_btn.setObjectName("copyBtn")
        regen_btn.clicked.connect(self.regenerate_password)
        
        use_btn = QPushButton("✓ Использовать этот")
        use_btn.setStyleSheet("background-color: #03dac6; color: #000; padding: 8px 16px;")
        use_btn.clicked.connect(self.use_generated_password)
        
        copy_use_btns.addWidget(copy_btn)
        copy_use_btns.addWidget(regen_btn)
        copy_use_btns.addWidget(use_btn)
        
        pg_layout.addWidget(gen_label)
        pg_layout.addWidget(self.generated_pwd_display)
        pg_layout.addLayout(copy_use_btns)
        
        unlock_btn = QPushButton("ОТКРЫТЬ СЕЙФ")
        unlock_btn.setStyleSheet("padding: 14px; font-size: 14px;")
        unlock_btn.clicked.connect(self.unlock)
        
        # Счётчик попыток и предупреждения
        self.attempts_label = QLabel()
        self.attempts_label.setObjectName("attemptsLabel")
        self.attempts_label.setAlignment(Qt.AlignCenter)
        
        self.warning_label = QLabel()
        self.warning_label.setObjectName("warningLabel")
        self.warning_label.setAlignment(Qt.AlignCenter)
        self.warning_label.setWordWrap(True)
        self.warning_label.hide()
        
        lf_layout.addStretch()
        lf_layout.addWidget(title)
        lf_layout.addWidget(subtitle)
        lf_layout.addWidget(self.pwd_input)
        lf_layout.addWidget(self.pwd_confirm_input)
        lf_layout.addWidget(self.password_gen_frame)
        lf_layout.addWidget(unlock_btn)
        lf_layout.addWidget(self.attempts_label)
        lf_layout.addWidget(self.warning_label)
        lf_layout.addStretch()
        
        # --- ЭКРАН СЕЙФА ---
        self.vault_frame = QFrame()
        self.vault_frame.setVisible(False)
        vf_layout = QVBoxLayout(self.vault_frame)
        
        self.drop_zone = QLabel("📥 Перетащите сюда для добавления в КОРЕНЬ сейфа")
        self.drop_zone.setObjectName("dropZone")
        self.drop_zone.setAlignment(Qt.AlignCenter)
        self.drop_zone.setAcceptDrops(True)
        self.drop_zone.dragEnterEvent = self.on_drag_enter_zone
        self.drop_zone.dragLeaveEvent = lambda e: self._set_drag_zone(False)
        self.drop_zone.dropEvent = self.on_drop_zone
        
        toolbar = QHBoxLayout()
        new_folder_btn = QPushButton("📁 Новая папка")
        new_folder_btn.setObjectName("folderBtn")
        new_folder_btn.clicked.connect(self.create_folder)
        
        delete_btn = QPushButton("🗑 Удалить выбранное")
        delete_btn.setObjectName("deleteBtn")
        delete_btn.clicked.connect(self.delete_selected)
        
        extract_all_btn = QPushButton("📦 Извлечь все")
        extract_all_btn.setObjectName("extractBtn")
        extract_all_btn.clicked.connect(self.extract_all)
        
        toolbar.addWidget(new_folder_btn)
        toolbar.addWidget(delete_btn)
        toolbar.addWidget(extract_all_btn)
        toolbar.addStretch()
        
        self.file_tree = DraggableTreeWidget(self.crypto, lambda: self.current_index)
        
        hint_label = QLabel("💡 Двойной клик — открыть | Drag из сейфа — экспорт | ПКМ — меню")
        hint_label.setStyleSheet("color: #666; font-size: 11px; font-style: italic;")
        hint_label.setWordWrap(True)
        
        close_btn = QPushButton("🔒 ЗАШИФРОВАТЬ И ЗАКРЫТЬ")
        close_btn.setObjectName("closeBtn")
        close_btn.setStyleSheet("padding: 14px; font-size: 14px;")
        close_btn.clicked.connect(self.lock)
        
        vf_layout.addWidget(self.drop_zone)
        vf_layout.addLayout(toolbar)
        vf_layout.addWidget(self.file_tree)
        vf_layout.addWidget(hint_label)
        vf_layout.addWidget(close_btn)
        
        layout.addWidget(self.login_frame)
        layout.addWidget(self.vault_frame)
        self.setStyleSheet(STYLESHEET)
        self._setup_login_screen()
    
    def copy_generated_password(self):
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(self.generated_pwd_display.text())
        QMessageBox.information(self, "Скопировано", "Пароль скопирован в буфер обмена.\n\n⚠ Обязательно сохраните его в надёжном месте!")
    
    def regenerate_password(self):
        self.generated_pwd_display.setText(CryptoEngine.generate_strong_password(50))
    
    def use_generated_password(self):
        pwd = self.generated_pwd_display.text()
        self.pwd_input.setText(pwd)
        self.pwd_confirm_input.setText(pwd)
        QMessageBox.information(
            self, "Пароль установлен",
            "Пароль установлен в поля ввода.\n\n⚠ ВАЖНО: Сохраните его в надёжном месте!\n"
            "После 10 неверных попыток сейф будет НЕВОССТАНОВИМО уничтожен."
        )
        self.pwd_input.setFocus()
        
    def _setup_login_screen(self):
        if self.crypto.is_new_vault():
            self.pwd_input.setPlaceholderText("Создайте мастер-пароль (или используйте сгенерированный)...")
            self.pwd_confirm_input.setVisible(True)
            self.password_gen_frame.setVisible(True)
            self.attempts_label.hide()
            self.warning_label.hide()
            # Регенерируем пароль при каждом показе
            self.generated_pwd_display.setText(CryptoEngine.generate_strong_password(50))
        elif self.crypto.is_destroyed():
            self.pwd_input.setVisible(False)
            self.pwd_confirm_input.setVisible(False)
            self.password_gen_frame.setVisible(False)
            self.warning_label.setText(
                "☠ СЕЙФ САМОУНИЧТОЖЕН\n\n"
                f"Превышено количество попыток ({MAX_ATTEMPTS}).\n"
                "Master key и соль уничтожены.\n"
                "Все данные криптографически невосстановимы.\n\n"
                "Для создания нового сейфа удалите папку ./secure_vault_data"
            )
            self.warning_label.show()
            self.attempts_label.hide()
        else:
            self.pwd_input.setPlaceholderText("Введите мастер-пароль...")
            self.pwd_confirm_input.setVisible(False)
            self.password_gen_frame.setVisible(False)
            self._update_attempts_display()
    
    def _update_attempts_display(self):
        remaining = self.crypto.get_remaining_attempts()
        used = MAX_ATTEMPTS - remaining
        
        if used == 0:
            self.attempts_label.hide()
            self.warning_label.hide()
        else:
            self.attempts_label.show()
            self.attempts_label.setText(
                f"⚠ Использовано попыток: {used} из {MAX_ATTEMPTS} "
                f"(осталось: {remaining})"
            )
            
            # Цвет и предупреждения в зависимости от количества
            if remaining <= 3:
                self.attempts_label.setProperty("class", "critical")
                self.attempts_label.setStyleSheet("color: #ff5252; font-size: 13px; font-weight: 700;")
                self.warning_label.show()
                self.warning_label.setText(
                    f"⚠ КРИТИЧНО! Осталось {remaining} попыток.\n"
                    "После превышения лимита сейф будет НЕВОССТАНОВИМО уничтожен."
                )
            elif remaining <= 5:
                self.attempts_label.setStyleSheet("color: #ffab40; font-size: 13px; font-weight: 600;")
                self.warning_label.show()
                self.warning_label.setText(
                    f"⚠ Внимание! Осталось {remaining} попыток.\n"
                    "Проверьте правильность пароля перед следующей попыткой."
                )
            else:
                self.attempts_label.setStyleSheet("color: #ffab40; font-size: 12px; font-weight: 600;")
                self.warning_label.hide()
        
        # Перерисовка
        self.attempts_label.style().unpolish(self.attempts_label)
        self.attempts_label.style().polish(self.attempts_label)
        
    def unlock(self):
        pwd = self.pwd_input.text()
        
        if not pwd:
            QMessageBox.warning(self, "Ошибка", "Введите пароль")
            return
        
        # Создание нового сейфа
        if self.crypto.is_new_vault():
            if len(pwd) < 12:
                QMessageBox.warning(
                    self, "Слабый пароль",
                    "Пароль слишком короткий!\n\n"
                    "Рекомендуется минимум 16 символов или использование сгенерированного пароля (50 символов).\n\n"
                    "Продолжить с этим паролем?",
                    QMessageBox.Yes | QMessageBox.No
                )
                # Для простоты — даём продолжить, но предупредили
            
            pwd_confirm = self.pwd_confirm_input.text()
            if pwd != pwd_confirm:
                QMessageBox.warning(self, "Ошибка", "Пароли не совпадают!")
                self.pwd_confirm_input.clear()
                return
            
            try:
                self.crypto.create_vault(pwd)
                self.current_index = {"items": {}}
                self.crypto.save_index(self.current_index)
                self._refresh_tree()
                self.login_frame.hide()
                self.vault_frame.show()
                self.pwd_input.clear()
                self.pwd_confirm_input.clear()
                
                QMessageBox.information(
                    self, "Сейф создан ✓",
                    "Сейф успешно создан!\n\n"
                    f"🛡 Защита активна:\n"
                    f"• Crypto-shredding (master-key + KEK)\n"
                    f"• {MAX_ATTEMPTS} попыток до самоуничтожения\n"
                    f"• Tamper-evident счётчик\n"
                    f"• Argon2id (memory=128MB, time=4)\n\n"
                    "⚠ Сохраните пароль в надёжном месте!"
                )
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось создать сейф:\n{e}")
            return
        
        # Разблокировка существующего сейфа
        try:
            # Экспоненциальная задержка между попытками
            failed_count = MAX_ATTEMPTS - self.crypto.get_remaining_attempts()
            if failed_count > 0:
                delays = [0, 0, 0, 2, 3, 5, 8, 12, 18, 30]
                delay = delays[min(failed_count, len(delays) - 1)]
                if delay > 0:
                    self.pwd_input.setEnabled(False)
                    self.pwd_input.setPlaceholderText(f"⏳ Ожидание защиты: {delay} сек...")
                    QApplication.processEvents()
                    time.sleep(delay)
                    self.pwd_input.setEnabled(True)
                    self.pwd_input.setPlaceholderText("Введите мастер-пароль...")
            
            success = self.crypto.unlock(pwd)
            
            if success:
                self.current_index = self.crypto.load_index()
                self._refresh_tree()
                self.login_frame.hide()
                self.vault_frame.show()
                self.pwd_input.clear()
                self._last_failed_attempt = 0
            else:
                remaining = self.crypto.get_remaining_attempts()
                QMessageBox.warning(
                    self, "Неверный пароль",
                    f"Неверный пароль!\n\n"
                    f"Осталось попыток: {remaining} из {MAX_ATTEMPTS}\n"
                    f"{'⚠ КРИТИЧНО! Следующая неудача может уничтожить сейф!' if remaining <= 2 else ''}"
                )
                self.pwd_input.clear()
                self.pwd_input.setFocus()
                self._update_attempts_display()
                
        except DestroyedError as e:
            QMessageBox.critical(
                self, "☠ СЕЙФ УНИЧТОЖЕН",
                f"{str(e)}\n\n"
                "Master-ключ и соль были криптографически уничтожены.\n"
                "Данные невосстановимы даже при знании пароля.\n\n"
                "Для создания нового сейфа удалите папку ./secure_vault_data"
            )
            self.pwd_input.clear()
            self._setup_login_screen()
            
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось открыть сейф:\n{e}")
            self._update_attempts_display()
            
    def lock(self):
        self.crypto.save_index(self.current_index)
        self.crypto.master_key = None
        self.crypto.kek = None
        self.vault_frame.hide()
        self._setup_login_screen()
        self.pwd_input.clear()
        self.pwd_input.setFocus()
        self.login_frame.show()
    
    def extract_all(self):
        all_files = []
        self._collect_files(self.current_index.get("items", {}), [], all_files)
        
        if not all_files:
            QMessageBox.information(self, "Пустой сейф", "В сейфе нет файлов для извлечения")
            return
        
        dest_dir = QFileDialog.getExistingDirectory(
            self, 
            f"Выберите папку для извлечения ({len(all_files)} файлов)",
            str(Path.home())
        )
        
        if not dest_dir:
            return
        
        dest_path = Path(dest_dir)
        extracted = 0
        errors = []
        
        for rel_path_parts, file_info in all_files:
            try:
                enc_path = Path(file_info["path"])
                if not enc_path.exists():
                    errors.append(f"Файл не найден: {enc_path}")
                    continue
                
                target_dir = dest_path
                for part in rel_path_parts[:-1]:
                    target_dir = target_dir / part
                    target_dir.mkdir(exist_ok=True)
                
                target_file = target_dir / rel_path_parts[-1]
                enc_data = enc_path.read_bytes()
                dec_data = self.crypto.decrypt(enc_data)
                target_file.write_bytes(dec_data)
                extracted += 1
            except Exception as e:
                errors.append(f"Ошибка с {'/'.join(rel_path_parts)}: {e}")
        
        msg = f"✅ Успешно извлечено: {extracted} файлов"
        if errors:
            msg += f"\n\n⚠ Ошибок: {len(errors)}\n" + "\n".join(errors[:5])
        
        QMessageBox.information(self, "Извлечение завершено", msg)
    
    def _collect_files(self, node_dict, path_parts, result_list):
        for name, info in node_dict.items():
            if isinstance(info, dict):
                current_path = path_parts + [name]
                if info.get("type") == TYPE_FILE:
                    result_list.append((current_path, info))
                elif info.get("type") == TYPE_FOLDER:
                    self._collect_files(info.get("children", {}), current_path, result_list)
        
    def _refresh_tree(self):
        self.file_tree.clear()
        self._build_tree_node(self.current_index.get("items", {}), None)
        
    def _build_tree_node(self, node_dict, parent_item):
        for name, info in node_dict.items():
            if isinstance(info, dict):
                item_type = info.get("type", TYPE_FILE)
                item = QTreeWidgetItem(parent_item) if parent_item else QTreeWidgetItem(self.file_tree)
                item.setText(0, name)
                item.setData(0, ROLE_TYPE, item_type)
                
                if item_type == TYPE_FOLDER:
                    item.setSizeHint(0, QSize(0, 40))
                    item.setIcon(0, self.icon_provider.icon(QFileIconProvider.Folder))
                    item.setText(1, "📁 Папка")
                    children = info.get("children", {})
                    item.setText(2, f"{len(children)} эл.")
                    
                    btn = QToolButton()
                    btn.setText("Открыть")
                    btn.setStyleSheet("""
                        QToolButton {
                            background: #1e1e1e;
                            border: 1px solid #333;
                            border-radius: 4px;
                            padding: 4px 10px;
                            color: #bb86fc;
                            font-weight: 500;
                        }
                        QToolButton:hover {
                            background: #2d2d2d;
                            border-color: #bb86fc;
                        }
                    """)
                    btn.clicked.connect(lambda checked, it=item: self.open_folder(it))
                    self.file_tree.setItemWidget(item, 3, btn)
                    
                    item.setChildIndicatorPolicy(QTreeWidgetItem.ChildIndicatorPolicy.ShowIndicator)
                    self._build_tree_node(children, item)
                    
                    if len(children) == 0:
                        self._add_placeholder(item)
                else:
                    item.setIcon(0, self.icon_provider.icon(QFileIconProvider.File))
                    item.setText(1, "Файл")
                    item.setText(2, info.get("size", "?"))
                    item.setData(0, Qt.UserRole + 1, info.get("path", ""))
    
    def _add_placeholder(self, parent_folder):
        placeholder = QTreeWidgetItem(parent_folder)
        placeholder.setText(0, "📭 Пустая папка — перетащите файлы сюда")
        placeholder.setData(0, ROLE_TYPE, TYPE_PLACEHOLDER)
        placeholder.setSizeHint(0, QSize(0, 70))
        
        font = placeholder.font(0)
        font.setItalic(True)
        font.setPointSize(11)
        placeholder.setFont(0, font)
        placeholder.setForeground(0, QBrush(QColor("#777")))
        
        placeholder.setText(1, "")
        placeholder.setText(2, "")
        placeholder.setText(3, "")
        
        flags = placeholder.flags()
        flags &= ~Qt.ItemIsSelectable
        flags &= ~Qt.ItemIsDragEnabled
        placeholder.setFlags(flags)
        
        placeholder.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)
        placeholder.setTextAlignment(0, Qt.AlignLeft | Qt.AlignVCenter)
    
    def open_folder(self, item):
        if item.data(0, ROLE_TYPE) == TYPE_FOLDER:
            item.setExpanded(not item.isExpanded())
            self.file_tree.scrollToItem(item)
    
    def on_tree_changed(self):
        self.current_index["items"] = self._tree_to_dict(None)
        
    def _tree_to_dict(self, parent_item):
        result = {}
        items_to_iterate = []
        if parent_item is None:
            for i in range(self.file_tree.topLevelItemCount()):
                item = self.file_tree.topLevelItem(i)
                if item.data(0, ROLE_TYPE) != TYPE_PLACEHOLDER:
                    items_to_iterate.append(item)
        else:
            for i in range(parent_item.childCount()):
                item = parent_item.child(i)
                if item.data(0, ROLE_TYPE) != TYPE_PLACEHOLDER:
                    items_to_iterate.append(item)
        for item in items_to_iterate:
            name = item.text(0)
            item_type = item.data(0, ROLE_TYPE)
            if item_type == TYPE_FOLDER:
                children = self._tree_to_dict(item)
                result[name] = {"type": TYPE_FOLDER, "children": children}
            else:
                old_info = self._find_file_info(name, self.current_index.get("items", {}))
                result[name] = old_info if old_info else {"type": TYPE_FILE, "path": ""}
        return result
        
    def _find_file_info(self, name, node_dict):
        for key, value in node_dict.items():
            if key == name and isinstance(value, dict) and value.get("type") == TYPE_FILE:
                return value
            if isinstance(value, dict) and "children" in value:
                found = self._find_file_info(name, value["children"])
                if found:
                    return found
        return None
        
    def create_folder(self):
        folder_name, ok = QInputDialog.getText(self, "Новая папка", "Имя папки:")
        if ok and folder_name:
            if folder_name in self.current_index.get("items", {}):
                QMessageBox.warning(self, "Ошибка", "Папка с таким именем уже существует")
                return
            self.current_index.setdefault("items", {})[folder_name] = {
                "type": TYPE_FOLDER,
                "children": {}
            }
            self._refresh_tree()
            items = self.file_tree.findItems(folder_name, Qt.MatchExactly | Qt.MatchRecursive, 0)
            for it in items:
                if it.data(0, ROLE_TYPE) == TYPE_FOLDER:
                    it.setExpanded(True)
                    self.file_tree.setCurrentItem(it)
                    self.file_tree.scrollToItem(it)
                    break
            
    def delete_selected(self):
        items = [it for it in self.file_tree.selectedItems() 
                if it.data(0, ROLE_TYPE) != TYPE_PLACEHOLDER]
        if not items:
            QMessageBox.information(self, "Информация", "Выберите элементы для удаления")
            return
        reply = QMessageBox.question(
            self, "Подтверждение",
            f"Удалить {len(items)} элемент(ов)?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            for item in items:
                path_parts = []
                current = item
                while current:
                    if current.data(0, ROLE_TYPE) != TYPE_PLACEHOLDER:
                        path_parts.insert(0, current.text(0))
                    current = current.parent()
                
                index = self.current_index
                node = index.get("items", {})
                node_to_delete = None
                
                for part in path_parts:
                    if part in node:
                        node_to_delete = node[part]
                        node = node[part] if isinstance(node[part], dict) else {}
                    else:
                        break
                
                if node_to_delete and isinstance(node_to_delete, dict):
                    if node_to_delete.get("type") == TYPE_FILE:
                        self.crypto.delete_files_recursive({"_": node_to_delete})
                    elif node_to_delete.get("type") == TYPE_FOLDER:
                        self.crypto.delete_files_recursive(node_to_delete.get("children", {}))
                
                parent = item.parent()
                if parent:
                    parent.removeChild(item)
                else:
                    self.file_tree.takeTopLevelItem(self.file_tree.indexOfTopLevelItem(item))
            
            self.on_tree_changed()
        
    def _set_drag_zone(self, state: bool):
        self.drop_zone.setProperty("dragOver", state)
        self.drop_zone.style().unpolish(self.drop_zone)
        self.drop_zone.style().polish(self.drop_zone)
        
    def on_drag_enter_zone(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._set_drag_zone(True)
            
    def on_drop_zone(self, event: QDropEvent):
        self._set_drag_zone(False)
        added = 0
        for url in event.mimeData().urls():
            path = Path(url.toLocalFile())
            try:
                if path.is_file():
                    self._add_file_to_vault(path, self.current_index["items"])
                    added += 1
                elif path.is_dir():
                    self._add_folder_to_vault(path, self.current_index["items"])
                    added += 1
            except Exception as e:
                QMessageBox.warning(self, "Ошибка", f"Не удалось добавить {path.name}:\n{e}")
        if added > 0:
            self._refresh_tree()
            QMessageBox.information(self, "Готово", f"Добавлено в корень: {added}")
            
    def _add_file_to_vault(self, file_path: Path, parent_dict: dict):
        data = file_path.read_bytes()
        enc_data = self.crypto.encrypt(data)
        safe_name = file_path.name
        dest = self.crypto.vault_path / f"{secrets.token_hex(8)}_{safe_name}.enc"
        dest.write_bytes(enc_data)
        parent_dict[safe_name] = {
            "type": TYPE_FILE,
            "path": str(dest),
            "size": self._format_size(len(data))
        }
        
    def _add_folder_to_vault(self, folder_path: Path, parent_dict: dict):
        folder_name = folder_path.name
        children = {}
        for item in folder_path.iterdir():
            if item.is_file():
                self._add_file_to_vault(item, children)
            elif item.is_dir():
                self._add_folder_to_vault(item, children)
        parent_dict[folder_name] = {"type": TYPE_FOLDER, "children": children}
        
    def _format_size(self, size_bytes: int) -> str:
        for unit in ['Б', 'КБ', 'МБ', 'ГБ']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} ТБ"

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    win = VaultApp()
    win.show()
    sys.exit(app.exec())