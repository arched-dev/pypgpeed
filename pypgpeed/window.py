import configparser
import os
import re
import subprocess
import sys
import webbrowser

import pyperclip
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QThread
from PyQt6.QtGui import QAction, QGuiApplication
from PyQt6.QtWidgets import QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLabel, \
    QPushButton, QMessageBox, QDialog, QDialogButtonBox, QFileDialog, QCheckBox

from pypgpeed import decrypt_message, encrypt_message, encrypt_cleartext_message, verify_message, make_key
from pypgpeed.functions import get_stored_keys


class Settings:
    def __init__(self, ini_path):
        # Ensure the path ends with .ini (if that's preferred)
        if not ini_path.endswith(".ini"):
            ini_path += ".ini"

        self.ini_path = ini_path
        self.config = configparser.ConfigParser()

        if os.path.exists(self.ini_path):
            self.config.read(self.ini_path)
        else:
            # File does not exist, so create it with a [General] section
            self.config["General"] = {}
            self.sync()  # write out the initial config

        # In case the file existed but didn't include a [General] section,
        # we ensure it's present.
        if "General" not in self.config:
            self.config["General"] = {}

    def setValue(self, key, value):
        """
        Mimics Settings.setValue(key, value)
        Stores the value in the [General] section of the .ini file.
        """
        self.config["General"][key] = str(value)

    def value(self, key, default=None):
        """
        Mimics Settings.value(key, default)
        Reads the value from the [General] section. Returns `default` if not present.
        """
        return self.config["General"].get(key, default)

    def sync(self):
        """
        Mimics Settings.sync()
        Writes the config data out to the .ini file.
        """
        with open(self.ini_path, "w") as f:
            self.config.write(f)

copy_text = "Copy Text"
output_text = "Output:"

class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("About")

        QBtn = QDialogButtonBox.StandardButton.Ok

        self.buttonBox = QDialogButtonBox(QBtn)
        self.buttonBox.accepted.connect(self.accept)

        self.layout = QVBoxLayout()

        about_label = QLabel(
            """This is a PGP tool designed for encryped messaging.\n\nBuilt with: \npyqt6 - graphical interface \npgpy - PGP encryption""")
        about_label.setWordWrap(True)

        self.layout.addWidget(about_label)
        self.layout.addWidget(self.buttonBox)
        self.setLayout(self.layout)


class GenerateDialog(QDialog):
    keys_generated = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Generate Keys")
        layout = QVBoxLayout()

        # Create widgets for "Generate Keys" tab
        self.passphrase_box = QTextEdit()
        self.passphrase_box.setTabChangesFocus(True)
        self.passphrase_box.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.passphrase_box.setFixedHeight(45)
        self.passphrase_box.setObjectName("gen_passphrase_box")

        self.name_box = QTextEdit()
        self.name_box.setTabChangesFocus(True)
        self.name_box.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.name_box.setFixedHeight(45)
        self.name_box.setObjectName("gen_name_box")

        self.email_box = QTextEdit()
        self.email_box.setTabChangesFocus(True)
        self.email_box.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.email_box.setFixedHeight(45)
        self.email_box.setObjectName("gen_email_box")

        self.output_location_box = QTextEdit()
        self.output_location_box.setTabChangesFocus(True)
        self.output_location_box.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.key_loc = self.parent().settings.value("key_location", None) or '~' + os.path.expanduser("/pgp_keys")
        self.output_location_box.setText(self.key_loc)
        self.output_location_box.setFixedHeight(45)
        self.output_location_box.setObjectName("gen_output_location_box")

        generate_button = QPushButton("Generate")
        generate_button.setObjectName("gen_generate_button")
        generate_button.clicked.connect(lambda: self.generate_key_validation())

        # Add widgets to layout
        layout.addWidget(QLabel("Create cryptographic keys for auth\n"))
        layout.addWidget(QLabel("Name (can be anything):"))
        layout.addWidget(self.name_box)
        layout.addWidget(QLabel("Email (doesn't have to be real):"))
        layout.addWidget(self.email_box)
        layout.addWidget(QLabel("Passphrase (must be secure):"))
        layout.addWidget(self.passphrase_box)
        layout.addWidget(QLabel("Output Location:"))
        layout.addWidget(self.output_location_box)
        layout.addWidget(generate_button)
        keys_saved_label = QLabel("")
        keys_saved_label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(keys_saved_label)
        layout.addStretch(1)

        self.setLayout(layout)

    def _create_key(self, name, email, passphrase, output_location):
        make_key(name, email, passphrase, output_location)
        self.keys_generated.emit(output_location)
        self.close()

    def generate_key_validation(self, test=False):
        def show_error(msg):
            if not test:
                QMessageBox.warning(self, "Error", msg)

        # Get the values from the text boxes
        name = self.name_box.toPlainText().strip()
        email = self.email_box.toPlainText().strip()
        passphrase = self.passphrase_box.toPlainText().strip()
        output_location = self.output_location_box.toPlainText().strip()

        # Check if the values are valid
        if not name:
            show_error("Please enter a name.")
            return False

        if len(name) <= 5:
            show_error("Please enter a longer name.")
            return False

        if not email:
            show_error("Please enter an email address.")
            return False

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            show_error("Please enter a valid email address.")
            return False

        if not passphrase:
            show_error("Please enter a passphrase.")
            return False

        if len(passphrase) < 8:
            show_error("Passphrase must be at least 8 characters long.")
            return False

        if not any(char.isupper() for char in passphrase):
            show_error("Passphrase must contain at least one uppercase letter.")
            return False

        if not any(char.islower() for char in passphrase):
            show_error("Passphrase must contain at least one lowercase letter.")
            return False

        if not any(char in "!@#$%^&*()_+{}[]|\:;<>,.?/~`" for char in passphrase):
            show_error("Passphrase must contain at least one special character.")
            return False

        if not output_location:
            show_error("Please enter an output location.")
            return False

        self._create_key(name, email, passphrase, output_location)
        return True

class PGP_Main(QMainWindow):

    shown_message: str = False

    def __init__(self, test=False, ini_path=None):
        super().__init__()

        # Decide where to load/save config.ini.
        # If ini_path is provided, use it; otherwise, default to app_dir/config.ini


        if ini_path and os.path.isdir(ini_path):
            ini_path = os.path.join(ini_path, "config.ini")

        if ini_path:
            if os.path.isfile(ini_path):
                #rename the file to have ini extension
                if not ini_path.endswith(".ini"):
                    os.rename(ini_path, ini_path + ".ini")
                    ini_path += ".ini"
            self.settings_path = ini_path
        else:
            home = os.path.expanduser("~")
            persis_path = os.path.join(home, "Persist")
            if os.path.isdir(persis_path):
                keys_path = os.path.join(persis_path, "pgp_keys")
                if not os.path.isdir(keys_path):
                    os.makedirs(keys_path)
                self.settings_path = os.path.join(persis_path, "config.ini")
            else:
                app_dir = os.path.dirname(os.path.abspath(__file__))
                self.settings_path = os.path.join(app_dir, "config.ini")

        self.settings = Settings(self.settings_path)
        # Load the key location if it was saved before
        self.key_location = self.settings.value("key_location", None)

        self.key_boxes = {"private": [], "public": []}
        if self.key_location:
            self.setup_keys()

        self.test_mode = test
        self.error_window = QMessageBox()
        self.error_window.setObjectName("error_window")

        # Creates an instance of the GenerateDialog window, need this here as need to access with unittests
        self.dlg = GenerateDialog(self)

        menubar = self.menuBar()

        # file menu bar
        file_menu = menubar.addMenu('File')

        # geneate new keys dialogue open
        generate_menu = QAction('Generate New Keys', self)
        generate_menu.triggered.connect(self.generate_show)
        generate_menu.setObjectName("generate_menu")

        file_menu.addAction(generate_menu)

        # set key location open
        set_menu = QAction('Set Key Location', self)
        set_menu.triggered.connect(self.set_key_location)
        file_menu.addAction(set_menu)

        # set key location open
        set_menu = QAction('Open Key Location', self)
        set_menu.triggered.connect(self.show_keys)
        file_menu.addAction(set_menu)

        # help menu
        edit_menu = menubar.addMenu('Help')

        # open about dialogue
        help_menu = QAction('About', self)
        help_menu.triggered.connect(self.help_show)

        # open homepage
        homepage_menu = QAction('Homepage', self)
        homepage_menu.triggered.connect(self.home_show)

        edit_menu.addAction(homepage_menu)
        edit_menu.addAction(help_menu)

        # sets the location of the key files for the private and publiuc keys
        # self.key_location = None
        # self.key_boxes = {"private": [], "public": []}
        self.copy_buttons = []

        # Set window title
        self.setWindowTitle("PGP")
        self.setFixedWidth(800)

        # Create tabs
        self.tabs = QTabWidget()
        self.decrypt_tab = QWidget()
        self.encrypt = QWidget()
        self.sign_tab = QWidget()
        self.verify_tab = QWidget()

        self.tabs.addTab(self.decrypt_tab, "Receive / Decrypt")
        self.tabs.addTab(self.encrypt, "Send / Encrypt")
        self.tabs.addTab(self.sign_tab, "Public / Sign")
        self.tabs.addTab(self.verify_tab, "Verify")

        # Create widgets for "DECRYPT" tab
        decrypt_message_box = QTextEdit()
        decrypt_message_box.setTabChangesFocus(True)
        decrypt_message_box.setObjectName("decrypt_message_box")

        decrypt_private_key_box = QTextEdit()
        self.key_boxes["private"].append(decrypt_private_key_box)
        decrypt_private_key_box.setObjectName("decrypt_private_key_box")

        decrypt_private_key_box.setTabChangesFocus(True)

        decrypt_output_box = QTextEdit()
        decrypt_output_box.setProperty('class', 'warning')
        decrypt_output_box.setReadOnly(True)
        decrypt_output_box.setObjectName("decrypt_output_box")

        decrypt_pass_box = QTextEdit()
        decrypt_pass_box.setTabChangesFocus(True)
        decrypt_pass_box.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        decrypt_pass_box.setFixedHeight(45)
        decrypt_pass_box.setObjectName("decrypt_pass_box")

        decrypt_widget = QWidget()
        decrypt_hbox = QHBoxLayout(decrypt_widget)

        copy_button_decrypt = QPushButton(copy_text)
        copy_button_decrypt.setObjectName("copy_button_decrypt")
        copy_button_decrypt.clicked.connect(
            lambda: self.copy_text(decrypt_output_box, copy_button_decrypt, True))
        copy_button_decrypt.setProperty('class', 'success')
        self.copy_buttons.append([decrypt_output_box, copy_button_decrypt])

        decrypt_button = QPushButton("Generate")
        decrypt_button.setProperty('class', 'warning')
        decrypt_button.clicked.connect(
            lambda: decrypt_message(decrypt_message_box.toPlainText(), decrypt_private_key_box.toPlainText(),
                                    decrypt_pass_box.toPlainText(),
                                    decrypt_output_box))
        decrypt_button.setObjectName("decrypt_button")

        decrypt_hbox.addWidget(decrypt_button)
        decrypt_hbox.addWidget(copy_button_decrypt)

        # Add widgets to layouts
        decrypt_layout = QVBoxLayout()
        decrypt_layout.addWidget(QLabel(
            "Decrypt messages sent to you by other people\nTake a PGP message that is garbage and turn it into real text.\n"))
        decrypt_layout.addWidget(QLabel("Their PGP Message:"))
        decrypt_layout.addWidget(decrypt_message_box)
        decrypt_layout.addWidget(QLabel("Your Private Key:"))
        decrypt_layout.addWidget(decrypt_private_key_box)
        decrypt_layout.addWidget(QLabel("Your Passphrase:"))
        decrypt_layout.addWidget(decrypt_pass_box)
        decrypt_layout.addWidget(QLabel(output_text))
        decrypt_layout.addWidget(decrypt_output_box)
        decrypt_layout.addWidget(decrypt_widget)

        self.decrypt_tab.setLayout(decrypt_layout)

        # Create widgets for "ENCRYPT" tab

        encrypt_message_box = QTextEdit()
        encrypt_message_box.setTabChangesFocus(True)
        encrypt_message_box.setObjectName("encrypt_message_box")


        encrypt_public_key_box = QTextEdit()
        encrypt_public_key_box.setTabChangesFocus(True)
        encrypt_public_key_box.setObjectName("encrypt_public_key_box")



        encrypt_output_box = QTextEdit()
        encrypt_output_box.setProperty('class', 'warning')
        encrypt_output_box.setReadOnly(True)
        encrypt_output_box.setObjectName("encrypt_output_box")


        encrypt_widget = QWidget()
        encrypt_hbox = QHBoxLayout(encrypt_widget)

        copy_button_encrypt = QPushButton(copy_text)
        copy_button_encrypt.clicked.connect(
            lambda: self.copy_text(encrypt_output_box, copy_button_encrypt))
        copy_button_encrypt.setProperty('class', 'success')
        self.copy_buttons.append([encrypt_output_box, copy_button_encrypt])
        copy_button_encrypt.setObjectName("copy_button_encrypt")


        encrypt_button = QPushButton("Generate")
        encrypt_button.setProperty('class', 'warning')
        encrypt_button.clicked.connect(
            lambda: encrypt_message(encrypt_message_box.toPlainText(), encrypt_public_key_box.toPlainText(),
                                    encrypt_output_box))
        encrypt_button.setObjectName("encrypt_button")

        encrypt_hbox.addWidget(encrypt_button)
        encrypt_hbox.addWidget(copy_button_encrypt)

        # Add widgets to layouts
        encrypt_layout = QVBoxLayout()
        encrypt_layout.addWidget(QLabel(
            "Encrypt messages to other people\nTake real text and make it into garbage that only be decrypted by someone with your pypgpeed public key.\n"))
        encrypt_layout.addWidget(QLabel("Your Message:"))
        encrypt_layout.addWidget(encrypt_message_box)
        encrypt_layout.addWidget(QLabel("Their Public Key:"))
        encrypt_layout.addWidget(encrypt_public_key_box)
        encrypt_layout.addWidget(QLabel(output_text))
        encrypt_layout.addWidget(encrypt_output_box)
        encrypt_layout.addWidget(encrypt_widget)

        self.encrypt.setLayout(encrypt_layout)

        # Create widgets for "SIGN" tab
        sign_message_box = QTextEdit()
        sign_message_box.setTabChangesFocus(True)
        sign_message_box.setObjectName("sign_message_box")

        sign_private_key_box = QTextEdit()
        self.key_boxes["private"].append(sign_private_key_box)
        sign_private_key_box.setTabChangesFocus(True)
        sign_private_key_box.setObjectName("sign_private_key_box")

        sign_output_box = QTextEdit()
        sign_output_box.setProperty('class', 'warning')
        sign_output_box.setReadOnly(True)
        sign_output_box.setObjectName("sign_output_box")

        sign_passphrase_box = QTextEdit()
        sign_passphrase_box.setFixedHeight(45)
        sign_passphrase_box.setTabChangesFocus(True)
        sign_passphrase_box.setObjectName("sign_passphrase_box")


        sign_widget = QWidget()
        sign_hbox = QHBoxLayout(sign_widget)

        copy_button_sign = QPushButton(copy_text)
        copy_button_sign.clicked.connect(
            lambda: self.copy_text(sign_output_box, copy_button_sign))
        copy_button_sign.setProperty('class', 'success')
        self.copy_buttons.append([sign_output_box, copy_button_sign])
        copy_button_sign.setObjectName("copy_button_sign")


        sign_button = QPushButton("Generate")
        sign_button.setProperty('class', 'warning')

        sign_button.clicked.connect(
            lambda: encrypt_cleartext_message(sign_message_box.toPlainText(), sign_private_key_box.toPlainText(),
                                              sign_passphrase_box.toPlainText(), sign_output_box))
        sign_button.setObjectName("sign_button")

        sign_hbox.addWidget(sign_button)
        sign_hbox.addWidget(copy_button_sign)

        # Add widgets to layouts
        sign_layout = QVBoxLayout()
        sign_layout.addWidget(QLabel(
            "Sign a message to prove it is you sending the message\nCreate a message that is visible but has been signed by you, prooving you are the writer of the message.\n"))
        sign_layout.addWidget(QLabel("Message:"))
        sign_layout.addWidget(sign_message_box)
        sign_layout.addWidget(QLabel("Your Private Key:"))
        sign_layout.addWidget(sign_private_key_box)
        sign_layout.addWidget(QLabel("Your Passphrase:"))
        sign_layout.addWidget(sign_passphrase_box)
        sign_layout.addWidget(QLabel(output_text))
        sign_layout.addWidget(sign_output_box)
        sign_layout.addWidget(sign_widget)


        self.sign_tab.setLayout(sign_layout)

        # Create widgets for "VERIFY" tab
        verify_message_box = QTextEdit()
        verify_message_box.setTabChangesFocus(True)
        verify_message_box.setObjectName("verify_message_box")

        verify_public_key_box = QTextEdit()
        self.key_boxes["public"].append(verify_public_key_box)
        verify_public_key_box.setTabChangesFocus(True)
        verify_public_key_box.setObjectName("verify_public_key_box")


        verify_output_box = QTextEdit()
        verify_output_box.setProperty('class', 'warning')
        verify_output_box.setReadOnly(True)
        verify_output_box.setObjectName("verify_output_box")


        verify_widget = QWidget()
        verify_hbox = QHBoxLayout(verify_widget)

        copy_button_verify = QPushButton(copy_text)
        copy_button_verify.clicked.connect(
            lambda: self.copy_text(verify_output_box, copy_button_verify))
        copy_button_verify.setProperty('class', 'success')
        self.copy_buttons.append([verify_output_box, copy_button_verify])
        copy_button_verify.setObjectName("copy_button_verify")

        verify_button = QPushButton("Generate")
        verify_button.setProperty('class', 'warning')
        verify_button.clicked.connect(
            lambda: verify_message(verify_message_box.toPlainText(), verify_public_key_box.toPlainText(),
                                   verify_output_box))
        verify_button.setObjectName("verify_button")


        verify_hbox.addWidget(verify_button)
        verify_hbox.addWidget(copy_button_verify)

        # Add widgets to layouts
        verify_layout = QVBoxLayout()
        verify_layout.addWidget(QLabel("Verify a signed message that has been sent\n"))
        verify_layout.addWidget(QLabel("Message:"))
        verify_layout.addWidget(verify_message_box)
        verify_layout.addWidget(QLabel("Their Public Key:"))
        verify_layout.addWidget(verify_public_key_box)
        verify_layout.addWidget(QLabel(output_text))
        verify_layout.addWidget(verify_output_box)
        verify_layout.addWidget(verify_widget)


        self.verify_tab.setLayout(verify_layout)

        # Set main layout and add tabs
        main_layout = QHBoxLayout()
        main_layout.addWidget(self.tabs)

        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        self.setup_keys()

    def _set_key(self, location):
        self.key_location = location
        self.settings.setValue("key_location", location)
        self.settings.sync()  # Save immediately

        if not self.test_mode:
            QMessageBox.information(self, "Keys generated", "New keys have been generated.")

        self.setup_keys(True)

    def set_key_location(self):
        loc = QFileDialog.getExistingDirectory(self, 'Select Folder', "/home")
        if loc:
            self.key_location = loc
            self.settings.setValue("key_location", loc)  # Save to settings
            self.settings.sync()  # Ensure it's written immediately

    def load_keys(self):
        self.setup_keys(True)

    def copy_text(self, textbox, copyButton, needs_pgp=True):
        # Copy the text from the text box to the clipboard
        text = textbox.toPlainText()
        if not text:
            if needs_pgp and not "---" in text or not needs_pgp:
                not self.test_mode and self.error_window.warning(self, "Error", "Nothing to copy...")
                return True

        clipboard = QGuiApplication.clipboard()
        try:
            clipboard.setText(text)
            pyperclip.copy(text)
        except:
            QMessageBox.warning(self, "Error", "Error copying")
            return

        # Change the button text to "Copied"
        copyButton.setText("Copied")

        # Wait for 3 seconds
        QTimer.singleShot(1500, self._return_box_to_normal)

    def show_keys(self):
        key_location = self.settings.value("key_location")

        if not key_location:
            QMessageBox.warning(self, "Error", "No key location set")
            return

        key_location = os.path.expanduser(key_location)  # Handle '~' in paths

        if not os.path.exists(key_location):
            QMessageBox.warning(self, "Error", "Key location does not exist")
            return

        try:
            if sys.platform == "win32":
                os.startfile(key_location)  # Windows
            elif sys.platform == "darwin":
                subprocess.Popen(["open", key_location])  # macOS
            else:
                subprocess.Popen(["xdg-open", key_location])  # Linux (including WSL)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to open directory: {e}")

    def _return_box_to_normal(self):
        for box in self.copy_buttons:
            # Change the button text back to copy_text
            box.setText(copy_text)

    def setup_keys(self, check=True):
        """adds the private and public keys to the window."""
        pri, pub = None, None
        if self.settings.value("key_location"):
            pri, pub = get_stored_keys(self.settings.value("key_location"))

        if check and (not pri or not pub):
            msg_box = QMessageBox()
            msg_box.setWindowTitle("Keys Error")
            msg_box.setText(
                f"It doesn't seem like you have any keys saved. Click file, and 'Set key location', then 'Generate New Keys' to create some.")
            # only show on run
            if self.shown_message is False:
                msg_box.exec()
                self.shown_message = True
            return False

        # loop items with pri or public keys
        for k, v in self.key_boxes.items():
            for el in v:
                if k == "private":
                    el.setText(pri.strip())
                else:
                    el.setText(pub.strip())
        return True

    def help_show(self):
        # Creates an instance of the AboutDialog window
        self.helpdlg = AboutDialog(self)
        # Executes the AboutDialog window
        not self.test_mode and self.helpdlg.exec()

    def home_show(self):
        # Defines a URL to be opened in the default web browser
        url = 'https://github.com/lewis-morris/pypgpeed'
        # Opens the specified URL in the default web browser
        webbrowser.open(url)

    def generate_show(self):
        # Connects the key_generated signal from the GenerateDialog to the on_key_generated slot of the parent window
        self.dlg.keys_generated.connect(self._set_key)
        # Executes the GenerateDialog window
        self.dlg.exec()
        self.load_keys()
        # Runs the setup_keys function after the

    def closeEvent(self, event):
        self.settings.sync()
        super().closeEvent(event)
