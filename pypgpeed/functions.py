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

    return box

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
    <svg id="eUPQjwNyvuK1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 300 300" shape-rendering="geometricPrecision" text-rendering="geometricPrecision"><g transform="matrix(1.013629 0 0 1-2.04435 0)"><rect width="304.033771" height="300" rx="0" ry="0" transform="matrix(.973465 0 0 1 2.016883 0.000001)" fill="#1de9b6" stroke-width="0"/></g><g transform="matrix(2.139627 0 0 1.701485-50.690608 1.400848)"><text dx="0" dy="0" font-family="&quot;eUPQjwNyvuK1:::Oswald&quot;" font-size="15" font-weight="700" transform="matrix(4.401275 0 0 7.425864 23.69134 131.988788)" fill="#31363b" stroke="#fff" stroke-width="0.4"><tspan y="0" font-weight="700" stroke-width="0.4"><![CDATA[
PGP
]]></tspan><tspan x="0" y="15" font-weight="700" stroke-width="0.4"><![CDATA[
 
]]></tspan></text></g>
<style><![CDATA[
@font-face {font-family: 'eUPQjwNyvuK1:::Oswald';font-style: normal;font-weight: 700;src: url(data:font/ttf;charset=utf-8;base64,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) format('truetype');}
]]></style>
</svg>

"""

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
