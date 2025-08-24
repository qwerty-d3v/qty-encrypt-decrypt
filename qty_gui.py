#!/usr/bin/env python3

import os, base64, sys, traceback
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"QTY1"
APP_TITLE = "QTY Encryptor (AES-GCM)"

def write_key_file(key_path: str, key: bytes):
    b64 = base64.urlsafe_b64encode(key)
    with open(key_path, "wb") as f:
        f.write(b64 + b"\n")
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass

def read_key_file(key_path: str) -> bytes:
    with open(key_path, "rb") as f:
        data = f.read().strip()
    try:
        return base64.urlsafe_b64decode(data)
    except Exception as e:
        raise ValueError("La .key no es base64 urlsafe válido") from e

def pack_blob(nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    aad_len = len(aad).to_bytes(2, "big")
    return MAGIC + nonce + aad_len + aad + ciphertext

def unpack_blob(blob: bytes):
    if len(blob) < 4 + 12 + 2:
        raise ValueError("Archivo .qty corrupto o incompleto")
    magic = blob[:4]
    if magic != MAGIC:
        raise ValueError("Formato desconocido (MAGIC inválido)")
    nonce = blob[4:16]
    aad_len = int.from_bytes(blob[16:18], "big")
    if 18 + aad_len > len(blob):
        raise ValueError("Archivo .qty corrupto (AAD)")
    aad = blob[18:18+aad_len]
    ciphertext = blob[18+aad_len:]
    return nonce, aad, ciphertext

def encrypt_file(in_path: str, out_qty: str, key_out: str):
    with open(in_path, "rb") as f:
        plaintext = f.read()

    key = os.urandom(32)
    nonce = os.urandom(12)
    aad = os.path.basename(in_path).encode("utf-8")

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    blob = pack_blob(nonce, aad, ciphertext)

    with open(out_qty, "wb") as f:
        f.write(blob)
    write_key_file(key_out, key)

def decrypt_file(qty_path: str, key_path: str, out_path: str):
    key = read_key_file(key_path)
    with open(qty_path, "rb") as f:
        blob = f.read()
    nonce, aad, ciphertext = unpack_blob(blob)

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

    with open(out_path, "wb") as f:
        f.write(plaintext)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("560x360")
        self.minsize(520, 340)
        try:
            self.iconbitmap(default=None)
        except Exception:
            pass

        self._make_styles()
        self._build_ui()

    def _make_styles(self):
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")

    def _build_ui(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=12, pady=12)

        self.encrypt_frame = ttk.Frame(nb, padding=12)
        self.decrypt_frame = ttk.Frame(nb, padding=12)
        nb.add(self.encrypt_frame, text="Cifrar")
        nb.add(self.decrypt_frame, text="Descifrar")

        self.in_file_var = tk.StringVar()
        self.out_qty_var = tk.StringVar()
        self.key_out_var = tk.StringVar()
        self.enc_status = tk.StringVar(value="Listo.")

        self._row_file_picker(self.encrypt_frame, "Archivo a cifrar:", self.in_file_var,
                              lambda: self._ask_open_file(self.in_file_var, title="Selecciona archivo a cifrar"))
        self._row_file_saver(self.encrypt_frame, "Guardar .qty como:", self.out_qty_var, ".qty")
        self._row_file_saver(self.encrypt_frame, "Guardar .key como:", self.key_out_var, ".key")

        ttk.Button(self.encrypt_frame, text="Cifrar", command=self.on_encrypt).grid(column=0, row=3, columnspan=3, pady=(10, 0), sticky="ew")
        ttk.Label(self.encrypt_frame, textvariable=self.enc_status, foreground="#2b6a30").grid(column=0, row=4, columnspan=3, sticky="w", pady=(8,0))

        for i in range(3):
            self.encrypt_frame.grid_columnconfigure(i, weight=1)

        self.qty_in_var = tk.StringVar()
        self.key_in_var = tk.StringVar()
        self.out_dec_var = tk.StringVar()
        self.dec_status = tk.StringVar(value="Listo.")

        self._row_file_picker(self.decrypt_frame, "Archivo .qty:", self.qty_in_var,
                              lambda: self._ask_open_file(self.qty_in_var, title="Selecciona archivo .qty", filetypes=[("QTY files", "*.qty"), ("Todos", "*.*")]))
        self._row_file_picker(self.decrypt_frame, "Archivo .key:", self.key_in_var,
                              lambda: self._ask_open_file(self.key_in_var, title="Selecciona archivo .key", filetypes=[("KEY files", "*.key"), ("Todos", "*.*")]))
        self._row_file_saver(self.decrypt_frame, "Guardar descifrado como:", self.out_dec_var, None)

        ttk.Button(self.decrypt_frame, text="Descifrar", command=self.on_decrypt).grid(column=0, row=3, columnspan=3, pady=(10, 0), sticky="ew")
        ttk.Label(self.decrypt_frame, textvariable=self.dec_status, foreground="#2b6a30").grid(column=0, row=4, columnspan=3, sticky="w", pady=(8,0))

        for i in range(3):
            self.decrypt_frame.grid_columnconfigure(i, weight=1)

        footer = ttk.Frame(self, padding=(12,0,12,12))
        footer.pack(fill="x")
        ttk.Label(footer, text="AES-GCM 256 • Clave única por archivo • Formato .qty v1").pack(side="left")
        ttk.Button(footer, text="Acerca de", command=self.on_about).pack(side="right")

        self.in_file_var.trace_add("write", self._suggest_outputs)

    def _row_file_picker(self, parent, label, var, cmd_btn):
        r = self._next_row(parent)
        ttk.Label(parent, text=label).grid(column=0, row=r, sticky="w", pady=4)
        ttk.Entry(parent, textvariable=var).grid(column=1, row=r, sticky="ew", padx=6)
        ttk.Button(parent, text="Elegir...", command=cmd_btn).grid(column=2, row=r, sticky="ew")

    def _row_file_saver(self, parent, label, var, default_ext):
        r = self._next_row(parent)
        ttk.Label(parent, text=label).grid(column=0, row=r, sticky="w", pady=4)
        ttk.Entry(parent, textvariable=var).grid(column=1, row=r, sticky="ew", padx=6)
        def _ask():
            initfile = None
            if var.get():
                initfile = os.path.basename(var.get())
            path = filedialog.asksaveasfilename(
                title=label,
                initialfile=initfile,
                defaultextension=default_ext if default_ext else "",
                filetypes=[("Todos", "*.*")])
            if path:
                var.set(path)
        ttk.Button(parent, text="Guardar como...", command=_ask).grid(column=2, row=r, sticky="ew")

    def _next_row(self, parent):
        # cuenta filas existentes
        children = [c for c in parent.grid_slaves() if int(c.grid_info()["row"]) >= 0]
        return (max([int(c.grid_info()["row"]) for c in children], default=-1) + 1)

    def _ask_open_file(self, target_var, title="Selecciona archivo", filetypes=[("Todos", "*.*")]):
        path = filedialog.askopenfilename(title=title, filetypes=filetypes)
        if path:
            target_var.set(path)

    def _suggest_outputs(self, *_):
        p = self.in_file_var.get()
        if not p:
            return
        if not self.out_qty_var.get():
            self.out_qty_var.set(p + ".qty")
        if not self.key_out_var.get():
            self.key_out_var.set(p + ".key")

    def on_about(self):
        messagebox.showinfo(
            "Acerca de",
            "QTY Encryptor (AES-GCM 256)\n\n"
            "Formato .qty v1: MAGIC(4) | NONCE(12) | AADLEN(2) | AAD | CIPHERTEXT(+TAG)\n"
            "• La AAD es el nombre de archivo original.\n"
            "• La seguridad depende de la clave (.key). Consérvala a buen recaudo.\n"
            "Creado por qwerty."
        )

    def on_encrypt(self):
        in_path = self.in_file_var.get().strip()
        out_qty = self.out_qty_var.get().strip()
        key_out = self.key_out_var.get().strip()

        if not in_path or not os.path.isfile(in_path):
            messagebox.showerror("Error", "Selecciona un archivo de entrada válido.")
            return
        if not out_qty:
            out_qty = in_path + ".qty"
            self.out_qty_var.set(out_qty)
        if not key_out:
            key_out = in_path + ".key"
            self.key_out_var.set(key_out)
        if os.path.abspath(in_path) == os.path.abspath(out_qty):
            messagebox.showerror("Error", "La salida .qty no puede ser el mismo archivo de entrada.")
            return
        if os.path.exists(out_qty):
            if not messagebox.askyesno("Sobrescribir", f"Ya existe:\n{out_qty}\n¿Sobrescribir?"):
                return
        if os.path.exists(key_out):
            if not messagebox.askyesno("Sobrescribir", f"Ya existe:\n{key_out}\n¿Sobrescribir?"):
                return

        try:
            self.enc_status.set("Cifrando...")
            self.update_idletasks()
            encrypt_file(in_path, out_qty, key_out)
            self.enc_status.set(f"OK: creado\n• {out_qty}\n• {key_out}")
            messagebox.showinfo("Éxito", f"Archivo cifrado:\n{out_qty}\n\nClave guardada en:\n{key_out}")
        except Exception as e:
            self.enc_status.set("Error al cifrar.")
            traceback.print_exc()
            messagebox.showerror("Error al cifrar", f"{e}")
        finally:
            self.update_idletasks()

    def on_decrypt(self):
        qty_in = self.qty_in_var.get().strip()
        key_in = self.key_in_var.get().strip()
        out_dec = self.out_dec_var.get().strip()

        if not qty_in or not os.path.isfile(qty_in) or not qty_in.endswith(".qty"):
            messagebox.showerror("Error", "Selecciona un archivo .qty válido.")
            return
        if not key_in or not os.path.isfile(key_in):
            messagebox.showerror("Error", "Selecciona un archivo .key válido.")
            return
        if not out_dec:
            out_dec = qty_in[:-4]
            self.out_dec_var.set(out_dec)
        if os.path.exists(out_dec):
            if not messagebox.askyesno("Sobrescribir", f"Ya existe:\n{out_dec}\n¿Sobrescribir?"):
                return

        try:
            self.dec_status.set("Descifrando...")
            self.update_idletasks()
            decrypt_file(qty_in, key_in, out_dec)
            self.dec_status.set(f"OK: creado\n• {out_dec}")
            messagebox.showinfo("Éxito", f"Archivo recuperado en:\n{out_dec}")
        except Exception as e:
            self.dec_status.set("Error al descifrar.")
            msg = str(e)
            if "Authentication" in msg or "tag" in msg.lower():
                msg = "Fallo de autenticación: clave incorrecta o archivo alterado/corrupto."
            traceback.print_exc()
            messagebox.showerror("Error al descifrar", msg)
        finally:
            self.update_idletasks()

def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
