import sys
import argparse
from PyQt6.QtWidgets import QApplication
from pypgpeed.functions import set_logo
from qt_material import apply_stylesheet

from pypgpeed.window import PGP_Main


def run(test=False, ini_path=None):
    """Runs the GUI app, test mode purely for unit testing."""
    app = QApplication(sys.argv)
    window = PGP_Main(test=test, ini_path=ini_path)
    window.setWindowTitle("pypgpeed")
    set_logo(app)
    apply_stylesheet(app, theme='dark_teal.xml', extra={"density_scale": 0.5})

    # Only show if we're not in test mode
    if not test:
        window.show()
        sys.exit(app.exec())

    return window, app

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run pypgpeed GUI")
    parser.add_argument("-i", "--ini", help="Path to config.ini file", default=None)
    args = parser.parse_args()
    print(args.ini)
    # Pass the user-supplied ini path (or None) to run()
    run(ini_path=args.ini)
