"""
gui.py

Tkinter GUI front-end for the ASCON-128 Secure File Encryption System.

This module is presentation-only. Every cryptographic, hashing, and
metrics operation is delegated unmodified to the classes defined in
crypto_backend.py (KeyManager, AsconEncryptor, AsconDecryptor, Hasher,
IntegrityVerifier, CryptographicMetricsAnalyzer). No cryptographic
logic lives in this file.
"""

import os
import io
import time
import queue
import platform
import threading
import subprocess
import contextlib
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

import crypto_backend as backend


APP_TITLE = "Secure File Encryption System"
APP_SUBTITLE = "ASCON Lightweight Cryptography"


class SecureFileGUI:
    """Main application window."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_TITLE}  |  {APP_SUBTITLE}")
        self.root.geometry("1000x700")
        self.root.minsize(900, 620)

        # ── Backend objects — cryptographic logic is untouched ──────
        self.key_manager = backend.KeyManager()
        self.encryptor   = backend.AsconEncryptor()
        self.decryptor   = backend.AsconDecryptor()
        self.hasher      = backend.Hasher()
        self.verifier    = backend.IntegrityVerifier()
        self.metrics     = backend.CryptographicMetricsAnalyzer()

        self.selected_file = None
        self._queue = queue.Queue()
        self._buttons = []
        self._busy = False

        self._configure_style()
        self._build_header()
        self._build_body()
        self._build_statusbar()

        self.root.after(100, self._poll_queue)

        self._log(f"Ready.  Algorithm: {backend.VARIANT}  |  "
                   f"Key: {backend.KEY_SIZE * 8}-bit  |  "
                   f"Nonce: {backend.NONCE_SIZE * 8}-bit\n", "head")
        self._log("NIST Lightweight Cryptography Standard\n", "info")
        self._log("-" * 78 + "\n")

    # ────────────────────────────────────────────────────────────
    # UI CONSTRUCTION
    # ────────────────────────────────────────────────────────────

    def _configure_style(self):
        style = ttk.Style()
        for theme in ("clam",):
            try:
                style.theme_use(theme)
                break
            except tk.TclError:
                continue

        style.configure("Header.TFrame", background="#1b2838")
        style.configure("HeaderTitle.TLabel", background="#1b2838",
                         foreground="#ffffff", font=("Segoe UI", 18, "bold"))
        style.configure("HeaderSub.TLabel", background="#1b2838",
                         foreground="#9fd3c7", font=("Segoe UI", 10))
        style.configure("Side.TFrame", background="#f4f6f8")
        style.configure("SideLabel.TLabel", background="#f4f6f8", font=("Segoe UI", 11, "bold"))
        style.configure("TButton", font=("Segoe UI", 10), padding=6)
        style.configure("Status.TLabel", font=("Segoe UI", 9))

    def _build_header(self):
        header = ttk.Frame(self.root, style="Header.TFrame", padding=(20, 14))
        header.pack(side="top", fill="x")

        title_box = ttk.Frame(header, style="Header.TFrame")
        title_box.pack(side="left", fill="x", expand=True)
        ttk.Label(title_box, text=APP_TITLE, style="HeaderTitle.TLabel").pack(anchor="w")
        ttk.Label(
            title_box,
            text=f"{APP_SUBTITLE}   •   NIST Lightweight Cryptography Standard   •   Final Year Project",
            style="HeaderSub.TLabel",
        ).pack(anchor="w", pady=(2, 0))

        algo_box = ttk.Frame(header, style="Header.TFrame")
        algo_box.pack(side="right")
        ttk.Label(algo_box, text=f"Algorithm: {backend.VARIANT}",
                  style="HeaderSub.TLabel").pack(anchor="e")
        ttk.Label(algo_box, text=f"Key: {backend.KEY_SIZE * 8}-bit   |   Nonce: {backend.NONCE_SIZE * 8}-bit",
                  style="HeaderSub.TLabel").pack(anchor="e")

    def _build_body(self):
        body = ttk.Frame(self.root, padding=10)
        body.pack(side="top", fill="both", expand=True)

        # ── LEFT PANEL ────────────────────────────────────────────
        left = ttk.Frame(body, style="Side.TFrame", padding=12, width=240)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        ttk.Label(left, text="Operations", style="SideLabel.TLabel").pack(anchor="w", pady=(0, 8))

        self.file_label_var = tk.StringVar(value="No file selected")
        file_frame = ttk.LabelFrame(left, text="Current File", padding=8)
        file_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(file_frame, textvariable=self.file_label_var, wraplength=195,
                  font=("Segoe UI", 8)).pack(anchor="w", pady=(0, 6))
        self._add_button(file_frame, "Browse File", self.action_browse_file)

        ops_frame = ttk.LabelFrame(left, text="Cryptographic Operations", padding=8)
        ops_frame.pack(fill="x", pady=(0, 10))
        self._add_button(ops_frame, "Generate Secret Key", self.action_generate_key)
        self._add_button(ops_frame, "Encrypt File", self.action_encrypt)
        self._add_button(ops_frame, "Decrypt File", self.action_decrypt)
        self._add_button(ops_frame, "Generate SHA-256 Hash", self.action_generate_hash)
        self._add_button(ops_frame, "Verify Hash", self.action_verify_hash)
        self._add_button(ops_frame, "Verify File Integrity", self.action_verify_integrity)

        metrics_frame = ttk.LabelFrame(left, text="Metrics", padding=8)
        metrics_frame.pack(fill="x", pady=(0, 10))
        self._add_button(metrics_frame, "View Metrics", self.action_view_metrics)
        self._add_button(metrics_frame, "Export Metrics", self.action_export_metrics)

        util_frame = ttk.LabelFrame(left, text="Utilities", padding=8)
        util_frame.pack(fill="x", pady=(0, 10))
        self._add_button(util_frame, "Open Encrypted Folder",
                          lambda: self.action_open_folder(backend.DIRS["encrypted"]))
        self._add_button(util_frame, "Open Decrypted Folder",
                          lambda: self.action_open_folder(backend.DIRS["decrypted"]))
        self._add_button(util_frame, "Open Metrics Folder",
                          lambda: self.action_open_folder(backend.DIRS["metrics"]))
        self._add_button(util_frame, "Clear Log", self.action_clear_log)

        self._add_button(left, "Exit", self.action_exit)

        # ── RIGHT PANEL ───────────────────────────────────────────
        right = ttk.Frame(body, padding=(12, 0, 0, 0))
        right.pack(side="left", fill="both", expand=True)

        ttk.Label(right, text="Activity Log", font=("Segoe UI", 11, "bold")).pack(anchor="w")

        self.log_widget = scrolledtext.ScrolledText(
            right, wrap="word", font=("Consolas", 10), state="disabled",
            background="#0f1720", foreground="#d7e2e8", insertbackground="#ffffff",
            borderwidth=0,
        )
        self.log_widget.pack(fill="both", expand=True, pady=(6, 0))
        self.log_widget.tag_configure("ok", foreground="#7CFC9A")
        self.log_widget.tag_configure("warn", foreground="#FFD166")
        self.log_widget.tag_configure("err", foreground="#FF6B6B")
        self.log_widget.tag_configure("info", foreground="#8ecae6")
        self.log_widget.tag_configure("head", foreground="#ffffff", font=("Consolas", 10, "bold"))

    def _build_statusbar(self):
        bar = ttk.Frame(self.root, padding=(10, 4))
        bar.pack(side="bottom", fill="x")

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(bar, textvariable=self.status_var, style="Status.TLabel").pack(side="left")

        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=220)
        self.progress.pack(side="right")

    def _add_button(self, parent, text, command):
        btn = ttk.Button(parent, text=text, command=command)
        btn.pack(fill="x", pady=3)
        self._buttons.append(btn)
        return btn

    # ────────────────────────────────────────────────────────────
    # LOGGING / STATUS HELPERS
    # ────────────────────────────────────────────────────────────

    def _log(self, text, tag=None):
        self.log_widget.configure(state="normal")
        if tag:
            self.log_widget.insert("end", text, tag)
        else:
            self.log_widget.insert("end", text)
        self.log_widget.see("end")
        self.log_widget.configure(state="disabled")

    def _log_result(self, metrics: dict, captured: str, heading: str):
        self._log(f"\n[{heading}]\n", "head")
        if captured.strip():
            self._log(captured if captured.endswith("\n") else captured + "\n")
        field_order = ("file", "file_size", "output_size", "key_size", "nonce_size",
                       "algorithm", "hash", "stored_hash", "current_hash", "result",
                       "status", "time_ms", "output_path")
        for key in field_order:
            if key in metrics:
                self._log(f"    {key:12s}: {metrics[key]}\n", "info")
        self._log(f"    {'timestamp':12s}: {datetime.now().isoformat()}\n\n", "info")

    def _set_status(self, text):
        self.status_var.set(text)

    def _set_busy(self, busy: bool):
        self._busy = busy
        state = "disabled" if busy else "normal"
        for b in self._buttons:
            b.configure(state=state)
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    # ────────────────────────────────────────────────────────────
    # FILE PICKER
    # ────────────────────────────────────────────────────────────

    def _pick_file(self, title="Select file", initialdir=None, filetypes=None):
        filetypes = filetypes or [("All files", "*.*")]
        path = filedialog.askopenfilename(title=title, initialdir=initialdir, filetypes=filetypes)
        return path or None

    # ────────────────────────────────────────────────────────────
    # ASYNC TASK RUNNER (keeps the GUI responsive; ops run off-thread)
    # ────────────────────────────────────────────────────────────

    def _run_async(self, label, fn, *args):
        if self._busy:
            messagebox.showwarning("Busy", "Please wait for the current operation to finish.")
            return
        self._set_busy(True)
        self._set_status(f"{label}...")

        def worker():
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    result = fn(*args)
                self._queue.put(("ok", label, result, buf.getvalue()))
            except Exception as exc:
                self._queue.put(("err", label, exc, buf.getvalue()))

        threading.Thread(target=worker, daemon=True).start()

    def _poll_queue(self):
        try:
            while True:
                status, label, payload, captured = self._queue.get_nowait()
                self._set_busy(False)
                if status == "ok":
                    self._on_task_success(label, payload, captured)
                else:
                    self._on_task_error(label, payload, captured)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _on_task_success(self, label, result, captured):
        if isinstance(result, dict):
            self._log_result(result, captured, label)
            status = result.get("status") or result.get("result")
            if status in ("TAMPERED", "INVALID"):
                self._set_status(f"{label}: {status}")
                messagebox.showwarning(label, f"{label} finished — result: {status}.\nSee log for details.")
            else:
                self._set_status(f"{label} — Operation completed successfully")
                messagebox.showinfo(label, "Operation completed successfully.")
        else:
            if captured.strip():
                self._log(f"\n[{label}]\n", "head")
                self._log(captured + "\n")
            self._set_status(f"{label} — Operation completed successfully")
            messagebox.showinfo(label, "Operation completed successfully.")

    def _on_task_error(self, label, exc, captured):
        self._set_status("Error — see log")
        if captured.strip():
            self._log(f"\n[{label}]\n", "head")
            self._log(captured + "\n")
        self._log(f"    ERROR: {exc}\n\n", "err")
        messagebox.showerror(label, str(exc))

    # ────────────────────────────────────────────────────────────
    # ACTIONS
    # ────────────────────────────────────────────────────────────

    def action_browse_file(self):
        path = self._pick_file(title="Select a file")
        if not path:
            return
        p = Path(path)
        self.file_label_var.set(p.name)
        self.selected_file = str(p)
        size = p.stat().st_size if p.exists() else 0
        self._log("\n[File Selected]\n", "head")
        self._log(f"    name: {p.name}\n    path: {p}\n    size: {size:,} bytes\n\n", "info")
        self._set_status(f"Selected: {p.name}")

    def action_generate_key(self):
        if backend.KEY_FILE.exists():
            if not messagebox.askyesno(
                "Key Exists",
                "An ASCON secret key already exists.\nOverwrite it with a new key?",
            ):
                self._log("\nKey generation cancelled by user.\n\n", "warn")
                self._set_status("Key generation cancelled")
                return

        def task():
            t0 = time.perf_counter()
            key = self.key_manager.generate_secret_key()
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 4)
            metrics = {
                "operation": "ASCON Key Generation",
                "algorithm": backend.VARIANT,
                "key_size": backend.KEY_SIZE * 8,
                "key_hex": key.hex(),
                "time_ms": elapsed_ms,
                "timestamp": datetime.now().isoformat(),
                "status": "SUCCESS",
            }
            self.metrics.record(metrics)
            return metrics

        self._run_async("Generate Secret Key", task)

    def action_encrypt(self):
        path = self._pick_file(title="Select file to encrypt")
        if not path:
            return

        def task():
            metrics = self.encryptor.encrypt_file(path)
            self.metrics.record(metrics)
            return metrics

        self._run_async("Encrypt File", task)

    def action_decrypt(self):
        initialdir = str(backend.DIRS["encrypted"]) if backend.DIRS["encrypted"].exists() else None
        path = self._pick_file(
            title="Select encrypted file (.ascon)",
            initialdir=initialdir,
            filetypes=[("ASCON encrypted files", "*.ascon"), ("All files", "*.*")],
        )
        if not path:
            return

        def task():
            metrics = self.decryptor.decrypt_file(path)
            self.metrics.record(metrics)
            return metrics

        self._run_async("Decrypt File", task)

    def action_generate_hash(self):
        path = self._pick_file(title="Select file to hash")
        if not path:
            return

        def task():
            metrics = self.hasher.generate_hash(path)
            self.metrics.record(metrics)
            return metrics

        self._run_async("Generate SHA-256 Hash", task)

    def action_verify_hash(self):
        path = self._pick_file(title="Select file to verify")
        if not path:
            return

        def task():
            metrics = self.hasher.verify_hash(path)
            self.metrics.record(metrics)
            return metrics

        self._run_async("Verify Hash", task)

    def action_verify_integrity(self):
        path = self._pick_file(title="Select file to verify integrity")
        if not path:
            return

        def task():
            metrics = self.verifier.verify_file_integrity(path)
            self.metrics.record(metrics)
            return metrics

        self._run_async("Verify File Integrity", task)

    def action_view_metrics(self):
        def task():
            self.metrics.view_report()
            return None

        self._run_async("View Metrics", task)

    def action_export_metrics(self):
        dest = filedialog.asksaveasfilename(
            title="Export metrics report",
            defaultextension=".json",
            initialfile="metrics_report.json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not dest:
            return

        def task():
            self.metrics.export_report(dest)
            return None

        self._run_async("Export Metrics", task)

    def action_open_folder(self, path: Path):
        path.mkdir(parents=True, exist_ok=True)
        try:
            system = platform.system()
            if system == "Windows":
                os.startfile(str(path))  # noqa: E501 - Windows-only API
            elif system == "Darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            messagebox.showerror("Open Folder", f"Could not open folder:\n{exc}")

    def action_clear_log(self):
        self.log_widget.configure(state="normal")
        self.log_widget.delete("1.0", "end")
        self.log_widget.configure(state="disabled")
        self._set_status("Log cleared")

    def action_exit(self):
        if self._busy:
            messagebox.showwarning("Busy", "Please wait for the current operation to finish.")
            return
        if messagebox.askokcancel("Exit", "Exit Secure File Encryption System?"):
            self.root.destroy()
