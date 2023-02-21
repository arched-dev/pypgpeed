import sys

from PyQt6.QtWidgets import QApplication
from pypgpeed import PGP_Main
from pypgpeed.functions import set_logo
from qt_material import apply_stylesheet


def run(test=False):
    """Runs the GUI app, test mode purely for unit testing"""
    app = QApplication(sys.argv)
    window = PGP_Main()
    window.setWindowTitle("pygpgeed")
    set_logo(app)
    apply_stylesheet(app, theme='dark_teal.xml', extra={"density_scale": 0.5})
    if not test:
        window.show()
        sys.exit(app.exec())
        return
    return window, app

if __name__ == "__main__":
    run()