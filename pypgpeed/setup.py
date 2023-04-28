import sys
from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but it might need fine-tuning.
build_exe_options = {
    "packages": ["sys", "PyQt6"],
    "excludes": [],
    "include_files": []  # Add any additional files, like images or config files, here.
}

# GUI applications require a different base on Windows.
base = None
if sys.platform == "win32":
    base = "Win32GUI"

setup(
    name="Pypgpeed",
    version="1.0",
    description="PGP encryption and decryption, signing etc",
    options={"build_exe": build_exe_options},
    executables=[Executable("run.py", base=base)],
)