"""
main.py

Entry point for the ASCON-128 Secure File Encryption System GUI.

Run with:
    python main.py

Requirements:
    pip install ascon cryptography
"""

import tkinter as tk

from gui import SecureFileGUI


def main():
    root = tk.Tk()
    app = SecureFileGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.action_exit)
    root.mainloop()


if __name__ == "__main__":
    main()
