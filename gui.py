from typing import Callable, List
import PySimpleGUI as sg
from main import CipherKey, encrypt_file, decrypt_file
from abc import ABC, abstractmethod
import secrets
import os.path


class TabInstance(ABC):
    def __init__(self) -> None:
        super().__init__()
        self.status_setter: Callable[[str, str], None] = None

    @property
    def tab(self) -> sg.Tab:
        return sg.Tab(self.title(), self.layout())

    @abstractmethod
    def title(self) -> str:
        pass
    
    @abstractmethod
    def layout(self) -> list[list[sg.Element]]:
        pass

    @abstractmethod
    def init(self, window: sg.Window) -> None:
        pass

    @abstractmethod
    def update(self, window: sg.Window, event: str, values: dict) -> None:
        pass

    def set_status(self, status: str) -> None:
        if self.status_setter:
            self.status_setter(status)


###### KEYGEN ######
class TabKeygen(TabInstance):
    INPUT_ENCRYPT_KEY = f'{secrets.token_hex(1)}INPUT_ENCRYPT_KEY'
    BUTTON_TOGGLE_ENCRYPT_KEY = f'{secrets.token_hex(1)}BUTTON_TOGGLE_ENCRYPT_KEY'
    GHOST_INPUT_EXPORT_ENCRYPT_KEY = f'{secrets.token_hex(1)}INPUT_EXPORT_ENCRYPT_KEY'
    BUTTON_EXPORT_ENCRYPT_KEY = f'{secrets.token_hex(1)}BUTTON_EXPORT_ENCRYPT_KEY'
    BUTTON_COPY_ENCRYPT_KEY = f'{secrets.token_hex(1)}BUTTON_COPY_ENCRYPT_KEY'

    INPUT_DECRYPT_KEY = f'{secrets.token_hex(1)}INPUT_DECRYPT_KEY'
    BUTTON_TOGGLE_DECRYPT_KEY = f'{secrets.token_hex(1)}BUTTON_TOGGLE_DECRYPT_KEY'
    GHOST_INPUT_EXPORT_DECRYPT_KEY = f'{secrets.token_hex(1)}INPUT_EXPORT_DECRYPT_KEY'
    BUTTON_EXPORT_DECRYPT_KEY = f'{secrets.token_hex(1)}BUTTON_EXPORT_DECRYPT_KEY'
    BUTTON_COPY_DECRYPT_KEY = f'{secrets.token_hex(1)}BUTTON_COPY_DECRYPT_KEY'

    BUTTON_GENERATE_KEY = f'{secrets.token_hex(1)}BUTTON_GENERATE_KEY'
    BUTTON_CLEAR_KEY = f'{secrets.token_hex(1)}BUTTON_CLEAR_KEY'

    def __init__(self) -> None:
        super().__init__()
        self.encryption_key_visible = False
        self.decryption_key_visible = False
        self.key_encrypt: CipherKey = None
        self.key_decrypt: CipherKey = None
    
    def title(self) -> str:
        return "Key Generator"
    
    def layout(self) -> list[list[sg.Element]]:
        return [
            [sg.Frame("Encryption Key", [
                [sg.Input(key=self.INPUT_ENCRYPT_KEY, readonly=True)],
                [
                    sg.Button("Show/Hide", key=self.BUTTON_TOGGLE_ENCRYPT_KEY),
                    sg.Button("Copy", key=self.BUTTON_COPY_ENCRYPT_KEY),
                    sg.Input(key=self.GHOST_INPUT_EXPORT_ENCRYPT_KEY, do_not_clear=False, enable_events=True, visible=False),
                    sg.SaveAs("Export .key", key=self.BUTTON_EXPORT_ENCRYPT_KEY, file_types=(("Key file", "*.key"),)),
                ],
            ])],
            [sg.Frame("Decryption Key", [
                [sg.Input(key=self.INPUT_DECRYPT_KEY, readonly=True)],
                [
                    sg.Button("Show/Hide", key=self.BUTTON_TOGGLE_DECRYPT_KEY),
                    sg.Button("Copy", key=self.BUTTON_COPY_DECRYPT_KEY),
                    sg.Input(key=self.GHOST_INPUT_EXPORT_DECRYPT_KEY, do_not_clear=False, enable_events=True, visible=False),
                    sg.SaveAs("Export .key", key=self.BUTTON_EXPORT_DECRYPT_KEY, file_types=(("Key file", "*.key"),)),
                ],
            ])],
            [sg.Button("Clear Keys", key=self.BUTTON_CLEAR_KEY, disabled=True)],
            [sg.Button("Generate Keys", key=self.BUTTON_GENERATE_KEY)],
        ]
    
    def init(self, window: sg.Window) -> None:
        window[self.INPUT_ENCRYPT_KEY].update(password_char='' if self.encryption_key_visible else '•')
        window[self.BUTTON_TOGGLE_ENCRYPT_KEY].update(disabled=True)
        window[self.BUTTON_EXPORT_ENCRYPT_KEY].update(disabled=True)
        window[self.BUTTON_COPY_ENCRYPT_KEY].update(disabled=True)

        window[self.INPUT_DECRYPT_KEY].update(password_char='' if self.decryption_key_visible else '•')
        window[self.BUTTON_TOGGLE_DECRYPT_KEY].update(disabled=True)
        window[self.BUTTON_EXPORT_DECRYPT_KEY].update(disabled=True)
        window[self.BUTTON_COPY_DECRYPT_KEY].update(disabled=True)
    
    def update(self, window: sg.Window, event: str, values: dict) -> None:
        if event == self.BUTTON_TOGGLE_ENCRYPT_KEY:
            self.encryption_key_visible = not self.encryption_key_visible
            window[self.INPUT_ENCRYPT_KEY].update(password_char='' if self.encryption_key_visible else '•')

        if event == self.BUTTON_TOGGLE_DECRYPT_KEY:
            self.decryption_key_visible = not self.decryption_key_visible
            window[self.INPUT_DECRYPT_KEY].update(password_char='' if self.decryption_key_visible else '•')

        if event == self.BUTTON_COPY_ENCRYPT_KEY and self.key_encrypt:
            sg.clipboard_set(self.key_encrypt.to_base64())
            self.set_status("Copied encryption key to clipboard")
        
        if event == self.BUTTON_COPY_DECRYPT_KEY and self.key_decrypt:
            sg.clipboard_set(self.key_decrypt.to_base64())
            self.set_status("Copied decryption key to clipboard")

        if event == self.GHOST_INPUT_EXPORT_ENCRYPT_KEY and self.key_encrypt:
            filename = values[self.GHOST_INPUT_EXPORT_ENCRYPT_KEY]
            if filename:
                try:
                    with open(filename, 'wb') as file:
                        file.write(self.key_encrypt.to_bytes())
                    self.set_status(f'Successfully exported encryption key')
                except:
                    self.set_status(f'Failed to export encryption key')
            else:
                self.set_status("No filename specified")

        if event == self.GHOST_INPUT_EXPORT_DECRYPT_KEY and self.key_decrypt:
            filename = values[self.GHOST_INPUT_EXPORT_DECRYPT_KEY]
            if filename:
                try:
                    with open(filename, 'wb') as file:
                        file.write(self.key_decrypt.to_bytes())
                    self.set_status(f'Successfully exported decryption key')
                except Exception as e:
                    self.set_status(f'Failed to export decryption key')
            else:
                self.set_status("No filename specified")
    
        if event == self.BUTTON_GENERATE_KEY:
            self.key_encrypt, self.key_decrypt = CipherKey.from_random()
            window[self.INPUT_ENCRYPT_KEY].update(self.key_encrypt.to_base64())
            window[self.INPUT_DECRYPT_KEY].update(self.key_decrypt.to_base64())
            window[self.BUTTON_TOGGLE_ENCRYPT_KEY].update(disabled=False)
            window[self.BUTTON_TOGGLE_DECRYPT_KEY].update(disabled=False)
            window[self.BUTTON_EXPORT_ENCRYPT_KEY].update(disabled=False)
            window[self.BUTTON_EXPORT_DECRYPT_KEY].update(disabled=False)
            window[self.BUTTON_COPY_ENCRYPT_KEY].update(disabled=False)
            window[self.BUTTON_COPY_DECRYPT_KEY].update(disabled=False)
            window[self.BUTTON_CLEAR_KEY].update(disabled=False)
            self.set_status("Keys generated")
        
        if event == self.BUTTON_CLEAR_KEY:
            self.key_encrypt = None
            self.key_decrypt = None
            window[self.INPUT_ENCRYPT_KEY].update('')
            window[self.INPUT_DECRYPT_KEY].update('')
            window[self.BUTTON_TOGGLE_ENCRYPT_KEY].update(disabled=True)
            window[self.BUTTON_TOGGLE_DECRYPT_KEY].update(disabled=True)
            window[self.BUTTON_EXPORT_ENCRYPT_KEY].update(disabled=True)
            window[self.BUTTON_EXPORT_DECRYPT_KEY].update(disabled=True)
            window[self.BUTTON_COPY_ENCRYPT_KEY].update(disabled=True)
            window[self.BUTTON_COPY_DECRYPT_KEY].update(disabled=True)
            window[self.BUTTON_CLEAR_KEY].update(disabled=True)
            self.set_status("Keys cleared")



###### FILE ENCRYPTOR ######
class TabFileEncryptor(TabInstance):
    INPUT_FILE_INPUT = f'{secrets.token_hex(1)}INPUT_FILE_INPUT'
    INPUT_FILE_OUTPUT = f'{secrets.token_hex(1)}INPUT_FILE_OUTPUT'
    INPUT_KEY = f'{secrets.token_hex(1)}INPUT_ENCRYPT_KEY'
    BUTTON_TOGGLE_KEY = f'{secrets.token_hex(1)}BUTTON_TOGGLE_ENCRYPT_KEY'
    BUTTON_PASTE_KEY = f'{secrets.token_hex(1)}BUTTON_PASTE_ENCRYPT_KEY'
    GHOST_INPUT_KEY = f'{secrets.token_hex(1)}GHOST_INPUT_ENCRYPT_KEY'
    BUTTON_ENCRYPT_FILE = f'{secrets.token_hex(1)}BUTTON_ENCRYPT_FILE'

    def __init__(self) -> None:
        super().__init__()
        self.key_clipboard_mode = False
        self.key_visible = False
    
    def title(self) -> str:
        return "File Encryptor"
    
    def layout(self) -> list[list[sg.Element]]:
        return [
            [sg.Frame("Import File Path", [
                [
                    sg.Input(key=self.INPUT_FILE_INPUT, enable_events=True),
                    sg.FileBrowse("Browse...", file_types=(("All Files", "*.*"),)),
                ],
            ])],
            [sg.Frame("Export File Path", [
                [
                    sg.Input(key=self.INPUT_FILE_OUTPUT, enable_events=True),
                    sg.FileSaveAs("Browse...", file_types=(("All Files", "*.*"),)),
                ],
            ])],
            [sg.Frame("Encryption Key", [
                [sg.Input(key=self.INPUT_KEY, readonly=True)],
                [
                    sg.Button("Show/Hide", key=self.BUTTON_TOGGLE_KEY),
                    sg.Button("Paste Key", key=self.BUTTON_PASTE_KEY),
                    sg.InputText(key=self.GHOST_INPUT_KEY, do_not_clear=False, enable_events=True, visible=False),
                    sg.FileBrowse("Import .key", file_types=(("Key file", "*.key"),)),
                ],
            ])],
            [sg.Button("Encrypt File", key=self.BUTTON_ENCRYPT_FILE)],
        ]

    def init(self, window: sg.Window) -> None:
        self.update_button_disabled(window)
        window[self.BUTTON_TOGGLE_KEY].update(disabled=True)

    def update(self, window: sg.Window, event: str, values: dict) -> None:
        if event == self.INPUT_FILE_INPUT or event == self.INPUT_FILE_OUTPUT or event == self.INPUT_KEY:
            self.update_button_disabled(window)
        
        if event == self.BUTTON_TOGGLE_KEY:
            self.key_visible = not self.key_visible
            window[self.INPUT_KEY].update(password_char='' if self.key_visible or not self.key_clipboard_mode else '•')
        
        if event == self.BUTTON_PASTE_KEY:
            self.key_clipboard_mode = True
            self.key_visible = False
            window[self.BUTTON_TOGGLE_KEY].update(disabled=False)
            window[self.INPUT_KEY].update(sg.clipboard_get(), password_char='' if self.key_visible or not self.key_clipboard_mode else '•')
            self.set_status("Pasted key from clipboard")
            self.update_button_disabled(window)
        
        if event == self.GHOST_INPUT_KEY:
            self.key_clipboard_mode = False
            window[self.BUTTON_TOGGLE_KEY].update(disabled=True)
            window[self.INPUT_KEY].update(values[self.GHOST_INPUT_KEY], password_char='' if self.key_visible or not self.key_clipboard_mode else '•')
            self.set_status("Imported key from key file")
            self.update_button_disabled(window)
        
        if event == self.BUTTON_ENCRYPT_FILE:
            self.encrypt_file(values)
    
    def encrypt_file(self, values: dict) -> None:
        input_path = values[self.INPUT_FILE_INPUT]
        output_path = values[self.INPUT_FILE_OUTPUT]
        key_path = values[self.INPUT_KEY]
        
        if not os.path.isfile(input_path):
            self.set_status("Error: Invalid input file path.")
            return
        
        if not os.path.isdir(os.path.dirname(output_path)):
            self.set_status("Error: Invalid output directory path.")
            return
        
        if not os.path.splitext(os.path.basename(output_path))[1]:
            self.set_status("Error: Output file path must include a file extension.")
            return
        
        key: CipherKey = None
        
        if self.key_clipboard_mode:
            try:
                key = CipherKey.from_base64(values[self.INPUT_KEY])
            except Exception as e:
                self.set_status("Error: Invalid key from clipboard.")
                return
        else:
            if not os.path.isfile(key_path):
                self.set_status("Error: Invalid key file path.")
                return
            try:
                with open(key_path, 'rb') as file:
                    key = CipherKey.from_bytes(file.read())
            except Exception as e:
                self.set_status("Error: Failed to load key from key path.")
                return
        
        try:
            self.set_status("Encrypting file...")
            encrypt_file(input_path, output_path, key)
            self.set_status(f'Successfully encrypted file')
        except Exception as e:
            self.set_status(f'Failed to encrypt file')

    def update_button_disabled(self, window: sg.Window) -> None:
        window[self.BUTTON_ENCRYPT_FILE].update(disabled=not (window[self.INPUT_FILE_INPUT].get() and window[self.INPUT_FILE_OUTPUT].get() and window[self.INPUT_KEY].get()))


###### FILE DECRYPTOR ######
class TabFileDecryptor(TabInstance):
    INPUT_FILE_INPUT = f'{secrets.token_hex(1)}INPUT_FILE_INPUT'
    INPUT_FILE_OUTPUT = f'{secrets.token_hex(1)}INPUT_FILE_OUTPUT'
    INPUT_KEY = f'{secrets.token_hex(1)}INPUT_DECRYPT_KEY'
    BUTTON_TOGGLE_KEY = f'{secrets.token_hex(1)}BUTTON_TOGGLE_DECRYPT_KEY'
    BUTTON_PASTE_KEY = f'{secrets.token_hex(1)}BUTTON_PASTE_DECRYPT_KEY'
    GHOST_INPUT_KEY = f'{secrets.token_hex(1)}GHOST_INPUT_DECRYPT_KEY'
    BUTTON_DECRYPT_FILE = f'{secrets.token_hex(1)}BUTTON_DECRYPT_FILE'

    def __init__(self) -> None:
        super().__init__()
        self.key_clipboard_mode = False
        self.key_visible = False
    
    def title(self) -> str:
        return "File Decryptor"
    
    def layout(self) -> list[list[sg.Element]]:
        return [
            [sg.Frame("Import File Path", [
                [
                    sg.Input(key=self.INPUT_FILE_INPUT, enable_events=True),
                    sg.FileBrowse("Browse...", file_types=(("All Files", "*.*"),)),
                ],
            ])],
            [sg.Frame("Export File Path", [
                [
                    sg.Input(key=self.INPUT_FILE_OUTPUT, enable_events=True),
                    sg.FileSaveAs("Browse...", file_types=(("All Files", "*.*"),)),
                ],
            ])],
            [sg.Frame("Decryption Key", [
                [sg.Input(key=self.INPUT_KEY, readonly=True)],
                [
                    sg.Button("Show/Hide", key=self.BUTTON_TOGGLE_KEY),
                    sg.Button("Paste Key", key=self.BUTTON_PASTE_KEY),
                    sg.InputText(key=self.GHOST_INPUT_KEY, do_not_clear=False, enable_events=True, visible=False),
                    sg.FileBrowse("Import .key", file_types=(("Key file", "*.key"),)),
                ],
            ])],
            [sg.Button("Decrypt File", key=self.BUTTON_DECRYPT_FILE)],
        ]

    def init(self, window: sg.Window) -> None:
        self.update_button_disabled(window)
        window[self.BUTTON_TOGGLE_KEY].update(disabled=True)

    def update(self, window: sg.Window, event: str, values: dict) -> None:
        if event == self.INPUT_FILE_INPUT or event == self.INPUT_FILE_OUTPUT or event == self.INPUT_KEY:
            self.update_button_disabled(window)
        
        if event == self.BUTTON_TOGGLE_KEY:
            self.key_visible = not self.key_visible
            window[self.INPUT_KEY].update(password_char='' if self.key_visible or not self.key_clipboard_mode else '•')
        
        if event == self.BUTTON_PASTE_KEY:
            self.key_clipboard_mode = True
            self.key_visible = False
            window[self.BUTTON_TOGGLE_KEY].update(disabled=False)
            window[self.INPUT_KEY].update(sg.clipboard_get(), password_char='' if self.key_visible or not self.key_clipboard_mode else '•')
            self.set_status("Pasted key from clipboard")
            self.update_button_disabled(window)
        
        if event == self.GHOST_INPUT_KEY:
            self.key_clipboard_mode = False
            window[self.BUTTON_TOGGLE_KEY].update(disabled=True)
            window[self.INPUT_KEY].update(values[self.GHOST_INPUT_KEY], password_char='' if self.key_visible or not self.key_clipboard_mode else '•')
            self.set_status("Imported key from key file")
            self.update_button_disabled(window)
        
        if event == self.BUTTON_DECRYPT_FILE:
            self.encrypt_file(values)
    
    def encrypt_file(self, values: dict) -> None:
        input_path = values[self.INPUT_FILE_INPUT]
        output_path = values[self.INPUT_FILE_OUTPUT]
        key_path = values[self.INPUT_KEY]
        
        if not os.path.isfile(input_path):
            self.set_status("Error: Invalid input file path.")
            return
        
        if not os.path.isdir(os.path.dirname(output_path)):
            self.set_status("Error: Invalid output directory path.")
            return
        
        if not os.path.splitext(os.path.basename(output_path))[1]:
            self.set_status("Error: Output file path must include a file extension.")
            return
        
        key: CipherKey = None
        
        if self.key_clipboard_mode:
            try:
                key = CipherKey.from_base64(values[self.INPUT_KEY])
            except Exception as e:
                self.set_status("Error: Invalid key from clipboard.")
                return
        else:
            if not os.path.isfile(key_path):
                self.set_status("Error: Invalid key file path.")
                return
            try:
                with open(key_path, 'rb') as file:
                    key = CipherKey.from_bytes(file.read())
            except Exception as e:
                self.set_status("Error: Failed to load key from key path.")
                return
        
        try:
            self.set_status("Decrypting file...")
            decrypt_file(input_path, output_path, key)
            self.set_status(f'Successfully decrypted file')
        except Exception as e:
            self.set_status(f'Failed to decrypt file')

    def update_button_disabled(self, window: sg.Window) -> None:
        window[self.BUTTON_DECRYPT_FILE].update(disabled=not (window[self.INPUT_FILE_INPUT].get() and window[self.INPUT_FILE_OUTPUT].get() and window[self.INPUT_KEY].get()))



###### MAIN WINDOW ######
if __name__ == "__main__":
    sg.theme("Dark2")
    tabs: List[TabInstance] = [TabKeygen(), TabFileEncryptor(), TabFileDecryptor()]
    window = sg.Window("Encryption Tool", finalize=True, layout=[
        [sg.TabGroup([[tab.tab] for tab in tabs])],
        [sg.StatusBar("Ready", key="status_bar", size=(None, 1))],
    ])

    for tab in tabs:
        tab.init(window)
        tab.status_setter = lambda status: window["status_bar"].update(status)

    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == "Exit":
            break
        
        for tab in tabs:
            tab.update(window, event, values)

    window.close()