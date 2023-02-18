import io
import os
import re


from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap, QPainter, QIcon
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtWidgets import QTextEdit


def get_box(*args, **kwargs):
    box = None
    for el in args:
        if isinstance(el, QTextEdit):
            box = el
    if "box" in kwargs:
        box = kwargs["box"]
    return box


def validate_password(password):
    regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return bool(re.match(regex, password))


def get_stored_keys(key_dir=None):
    # get the home directory path

    # set the keys directory path
    if not key_dir:
        key_dir = os.path.join(os.path.expanduser('~'), 'pgp_keys')

    # set the key file paths
    pub_key_path = os.path.join(key_dir, 'pub_key.key')
    pri_key_path = os.path.join(key_dir, 'pri_key.key')

    pub_key_str = ""
    pri_key_str = ""

    # check if the key files exist
    if os.path.exists(pub_key_path) and os.path.exists(pri_key_path):
        # load the public key file as a string
        with io.open(pub_key_path, 'r', encoding='utf-8') as pub_file:
            pub_key_str = pub_file.read()

        # load the private key file as a string
        with io.open(pri_key_path, 'r', encoding='utf-8') as pri_file:
            pri_key_str = pri_file.read()

    return pri_key_str, pub_key_str


def make_directory(path):
    """
    Create a directory and any necessary subdirectories if it doesn't already exist.
    """
    try:
        os.makedirs(path)
    except FileExistsError:
        # directory already exists
        pass
    except Exception as e:
        print(f"An error occurred while creating the directory: {str(e)}")


def set_logo(app):
    svg_data = """
    <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
      <rect x="10" y="10" width="80" height="80" rx="10" ry="10" fill="green"/>
      <text x="50" y="60" font-size="60" text-anchor="middle" fill="white">P</text>
    </svg>
    """
#     svg_data = """
#   <svg width="100" height="100" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
#   <rect x="0" y="0" width="100" height="100" fill="#1de9b6" />
#   <path fill="#31363b" stroke="#ffffff" stroke-width="2" d="M 23 40 L 23 60 L 28 60 L 28 53 L 37 53 L 37 60 L 42 60 L 42 40 L 37 40 L 37 47 L 28 47 L 28 40 L 23 40 Z M 52 60 L 52 40 L 47 40 L 47 60 L 52 60 Z M 59 60 L 64 60 Q 71 60 71 53 Q 71 49 67 46 Q 63 43 56 42 L 72 40 L 72 39 L 54 39 Q 52 39 52 37 Q 52 35 53 34 Q 54 33 57 33 L 72 30 L 72 29 L 56 29 Q 49 29 45 32 Q 41 35 41 42 Q 41 51 49 51 L 59 51 L 59 60 Z" />
# </svg>
#     """

    # Load the SVG data into a QPixmap
    renderer = QSvgRenderer(bytearray(svg_data, encoding='utf-8'))
    pixmap = QPixmap(100, 100)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()

    # Set the QPixmap as the application icon
    app.setWindowIcon(QIcon(pixmap))
    return