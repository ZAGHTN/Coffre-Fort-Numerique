# -*- coding: utf-8 -*-
import sys
import tkinter as tk
import datetime
import configparser
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.widgets import ToolTip
import os
from os import path
import zlib
import string
import secrets
from cryptography.exceptions import InvalidTag
import json
import urllib.request
import webbrowser
import threading

# Import de la logique métier
from crypto_logic import (
    encrypt_logic, decrypt_logic, verify_integrity_logic, secure_delete,
    TRANSLATIONS
)

APP_VERSION = "1.2"
APP_AUTHOR = "Zaghdoudi Chokri"
GITHUB_REPO = "ZAGHTN/Coffre-Fort-Numerique" # Votre dépôt GitHub
CURRENT_LANG = "fr" # Variable globale pour la langue

def resource_path(relative_path: str) -> str:
    """Obtient le chemin absolu de la ressource, fonctionne pour dev et PyInstaller."""
    try:
        # PyInstaller crée un dossier temporaire et stocke le chemin dans _MEIPASS
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = path.dirname(path.abspath(__file__))
    return path.join(base_path, relative_path)

def get_writable_path(filename: str) -> str:
    """Obtient le chemin absolu pour un fichier inscriptible (config, logs)."""
    if getattr(sys, 'frozen', False):
        # Si exécuté via PyInstaller (.exe), on utilise le dossier de l'exécutable
        base_path = os.path.dirname(sys.executable)
    else:
        # En développement, on utilise le dossier du script
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, filename)

# --- INTERFACE GRAPHIQUE (Tkinter) ---

class CryptoApp: # pragma: no cover
    def __init__(self, root):
        self.root = root
        self.current_lang = "fr" # Langue par défaut
        self.root.resizable(False, False)

        self.mode = ""
        self.current_theme = "superhero"
       
        # Ajout de l'icône personnalisée (si le fichier existe)
        # Support multiplateforme : PNG (via iconphoto) ou ICO (via iconbitmap)
        for ext in [".png", ".ico"]:
            icon_path = resource_path(f"cadenas{ext}")
            if os.path.exists(icon_path):
                if ext == ".png":
                    self.root.iconphoto(False, tk.PhotoImage(file=icon_path))
                else:
                    self.root.iconbitmap(icon_path)
                break

        # Gestion de la configuration (Position)
        self.config_file = get_writable_path("config.ini")
        self.load_config()
        self.root.title(self.tr("title"))
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.btn_encrypt = None
        self.btn_decrypt = None
        self.btn_verify = None
        self.show_welcome_screen()
        
        # Vérification automatique des mises à jour au démarrage (après 2 secondes)
        self.root.after(2000, lambda: self.check_updates(silent=True))

    def center_window(self, width, height, window=None):
        """Redimensionne et centre la fenêtre sur l'écran."""
        target = window if window else self.root
        target.update_idletasks()
        if not window:
            # Rendre la fenêtre transparente pour masquer le déplacement
            target.attributes("-alpha", 0.0)
        screen_width = target.winfo_screenwidth()
        screen_height = target.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 3
        target.geometry(f"{width}x{height}+{x}+{y}")
        if not window:
            # Réinitialiser l'apparence de la fenêtre
            target.attributes("-alpha", 1.0)

    def tr(self, key):
        """Récupère la traduction pour la clé donnée."""
        return TRANSLATIONS.get(self.current_lang, TRANSLATIONS["fr"]).get(key, key)

    def show_welcome_screen(self):
        """Affiche l'écran de sélection du mode."""
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Réinitialiser le menu
        menubar = tk.Menu(self.root)
        exit_menu = tk.Menu(menubar, tearoff=0)
        exit_menu.add_command(label=self.tr("quit"), command=self.on_closing)
        menubar.add_cascade(label=self.tr("quit"), menu=exit_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label=self.tr("dark"), command=lambda: self.change_theme("superhero"))
        view_menu.add_command(label=self.tr("light"), command=lambda: self.change_theme("cosmo"))
        view_menu.add_separator()
        
        # Sous-menu Langue
        lang_menu = tk.Menu(view_menu, tearoff=0)
        lang_menu.add_command(label="Français", command=lambda: self.change_language("fr"))
        lang_menu.add_command(label="English", command=lambda: self.change_language("en"))
        view_menu.add_cascade(label=self.tr("lang"), menu=lang_menu)
        
        menubar.add_cascade(label=self.tr("view"), menu=view_menu)

        self.root.config(menu=menubar)

        # Centrer la fenêtre d'accueil
        self.center_window(450, 250)
        
        ttk.Label(self.root, text=self.tr("welcome"), font=("Helvetica", 10, "bold"), bootstyle="info").pack(pady=20, fill=X)
        ttk.Label(self.root, text=self.tr("action_prompt"), font=("Helvetica", 10)).pack(pady=10)
        
        frame_buttons = ttk.Frame(self.root)
        frame_buttons.pack(pady=20)
        
        btn_enc = ttk.Button(frame_buttons, text=f" {self.tr('encrypt')}", width=15, bootstyle="danger-outline", command=lambda: self.setup_main_ui("encrypt"))
        btn_enc.pack(side=tk.LEFT, padx=10)
        ToolTip(btn_enc, text=self.tr("encrypt"), padding=3)
        
        btn_dec = ttk.Button(frame_buttons, text=f"🔓 {self.tr('decrypt')}", width=15, bootstyle="success-outline", command=lambda: self.setup_main_ui("decrypt"))
        btn_dec.pack(side=tk.LEFT, padx=10)
        ToolTip(btn_dec, text=self.tr("decrypt"), 
                padding=3)

    def load_config(self):
        """Charge la position de la fenêtre et le thème."""
        if os.path.exists(self.config_file):
            config = configparser.ConfigParser()
            config.read(self.config_file)
            if "Window" in config:
                x, y = config["Window"].get("x"), config["Window"].get("y")
                if x and y:
                    self.root.geometry(f"+{x}+{y}")
            if "Settings" in config:
                self.current_theme = config["Settings"].get("theme", "superhero")
                self.current_lang = config["Settings"].get("lang", "fr")
                global CURRENT_LANG
                CURRENT_LANG = self.current_lang
        
        try:
            self.root.style.theme_use(self.current_theme)
        except:
            pass

    def save_config(self):
        """Sauvegarde la position actuelle et le thème."""
        config = configparser.ConfigParser()
        if os.path.exists(self.config_file):
            config.read(self.config_file)
            
        if "Window" not in config: config["Window"] = {}
        config["Window"]["x"] = str(self.root.winfo_x())
        config["Window"]["y"] = str(self.root.winfo_y())
        
        if "Settings" not in config: config["Settings"] = {}
        config["Settings"]["theme"] = self.current_theme
        config["Settings"]["lang"] = self.current_lang
        
        with open(self.config_file, "w") as f:
            config.write(f)

    def change_theme(self, theme_name):
        """Change le thème de l'interface et sauvegarde."""
        self.current_theme = theme_name
        self.root.style.theme_use(theme_name)
        self.save_config()

    def change_language(self, lang):
        """Change la langue et rafraîchit l'interface."""
        self.current_lang = lang
        global CURRENT_LANG
        CURRENT_LANG = lang
        self.save_config()
        self.root.title(self.tr("title"))
        if self.mode:
            self.setup_main_ui(self.mode)
        else:
            self.show_welcome_screen()

    def on_closing(self):
        """Sauvegarde et quitte."""
        self.save_config()
        self.root.destroy()

    def show_about(self):
        """Affiche la fenêtre À propos."""
        msg = self.tr("about_msg").format(version=APP_VERSION, author=APP_AUTHOR)
        messagebox.showinfo(self.tr("about"), msg)
    
    def _is_version_newer(self, remote: str, current: str) -> bool:
        """Compare deux numéros de version (ex: '1.1' > '1.0')."""
        try:
            r_parts = [int(x) for x in remote.split('.')]
            c_parts = [int(x) for x in current.split('.')]
            return r_parts > c_parts
        except ValueError:
            return False

    def _ask_update(self, version, url):
        """Affiche la demande de mise à jour sur le thread principal."""
        if messagebox.askyesno("Mise à jour disponible", f"Une nouvelle version ({version}) est disponible !\n\nVoulez-vous la télécharger maintenant ?"):
            webbrowser.open(url)

    def _perform_update_check(self, silent=False):
        """Exécute la vérification réseau dans un thread séparé."""
        try:
            url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
            # GitHub exige un User-Agent pour l'API, sinon erreur 403
            req = urllib.request.Request(url, headers={'User-Agent': 'CoffreFortApp'})
            
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                latest_tag = data.get("tag_name", "").lower().lstrip("v") # Gère v1.0 et V1.0
                html_url = data.get("html_url", "")

            if self._is_version_newer(latest_tag, APP_VERSION):
                self.root.after(0, lambda: self._ask_update(latest_tag, html_url))
            else:
                if not silent:
                    self.root.after(0, lambda: messagebox.showinfo("Mise à jour", f"Vous utilisez la version {APP_VERSION}.\nC'est la dernière version disponible."))
        
        except Exception as e:
            if not silent:
                self.root.after(0, lambda: messagebox.showerror("Erreur", f"Impossible de vérifier les mises à jour.\n\nDétails : {e}"))

    def check_updates(self, silent=False):
        """Lance la vérification des mises à jour en arrière-plan."""
        threading.Thread(target=self._perform_update_check, args=(silent,), daemon=True).start()

    def show_logs(self):
        """Affiche le contenu du fichier journal dans une nouvelle fenêtre."""
        log_file = get_writable_path("historique_crypto.log")
        if not os.path.exists(log_file):
            messagebox.showinfo("Information", "Aucun historique disponible pour le moment.")
            return

        top = ttk.Toplevel(self.root)
        top.title(self.tr("hist_title"))
        self.center_window(700, 500, top)
        
        frame_txt = ttk.Frame(top)
        frame_txt.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        v_scroll = ttk.Scrollbar(frame_txt, orient="vertical")
        h_scroll = ttk.Scrollbar(frame_txt, orient="horizontal")

        text_area = tk.Text(frame_txt, width=80, height=20, font=("Consolas", 10), wrap="none",
                            yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        v_scroll.config(command=text_area.yview)
        h_scroll.config(command=text_area.xview)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        text_area.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        
        with open(log_file, "r", encoding="utf-8") as f:
            text_area.insert(tk.END, f.read())
        
        text_area.configure(state='disabled') # Lecture seule

        def clear_history():
            if messagebox.askyesno("Confirmation", self.tr("confirm_clear")):
                try:
                    open(log_file, 'w').close() # Vider le fichier
                    text_area.configure(state='normal')
                    text_area.delete('1.0', tk.END)
                    text_area.configure(state='disabled')
                    messagebox.showinfo(self.tr("success"), self.tr("hist_cleared"))
                except Exception as e:
                    messagebox.showerror(self.tr("error"), f"Impossible d'effacer le fichier : {e}")

        ttk.Button(top, text=self.tr("hist_clear"), bootstyle="danger-outline", command=clear_history).pack(pady=10)

    def setup_main_ui(self, mode: str) -> None:
        """Configure l'interface principale selon le mode choisi."""
        self.mode = mode
        for widget in self.root.winfo_children():
            widget.destroy()
        # Centrer la fenêtre principal
        self.center_window(600, 520) # Légèrement agrandi pour éviter que le bas soit coupé

        # Menu Fichier
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label=self.tr("main_menu"), command=self.show_welcome_screen)
        file_menu.add_command(label=self.tr("history"), command=self.show_logs)
        file_menu.add_separator()
        file_menu.add_command(label=self.tr("quit"), command=self.on_closing)
        menubar.add_cascade(label=self.tr("file"), menu=file_menu)

        # Menu Affichage
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label=self.tr("dark"), command=lambda: self.change_theme("superhero"))
        view_menu.add_command(label=self.tr("light"), command=lambda: self.change_theme("cosmo"))
        view_menu.add_separator()
        
        lang_menu = tk.Menu(view_menu, tearoff=0)
        lang_menu.add_command(label="Français", command=lambda: self.change_language("fr"))
        lang_menu.add_command(label="English", command=lambda: self.change_language("en"))
        view_menu.add_cascade(label=self.tr("lang"), menu=lang_menu)
        
        menubar.add_cascade(label=self.tr("view"), menu=view_menu)

        # Menu Aide
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label=self.tr("about"), command=self.show_about)
        help_menu.add_command(label=self.tr("update"), command=self.check_updates)
        menubar.add_cascade(label=self.tr("help"), menu=help_menu)

        self.root.config(menu=menubar)

        # Zone de sélection de fichier
        style_color = "danger" if self.mode == "encrypt" else "success"
        title_text = self.tr("mode_enc") if self.mode == "encrypt" else self.tr("mode_dec")
        
        ttk.Label(self.root, text=title_text, font=("Helvetica", 14, "bold"), bootstyle=style_color).pack(pady=(15, 10))
        
        # Groupe Fichiers
        lf_files = ttk.Labelframe(self.root, text=self.tr("sel_files"), padding=15, bootstyle=style_color)
        lf_files.pack(fill=tk.X, padx=20, pady=5)

        ttk.Label(lf_files, text=self.tr("src_file")).pack(anchor=tk.W)
        frame_input = ttk.Frame(lf_files)
        frame_input.pack(fill=tk.X, pady=(0, 10))
        
        self.file_var = tk.StringVar()
        self.file_var.trace_add("write", self.toggle_buttons)
        self.entry_file = ttk.Entry(frame_input, textvariable=self.file_var)
        self.entry_file.pack(side=tk.LEFT, fill=tk.X, expand=True)
        btn_browse = ttk.Button(frame_input, text="📂", command=self.browse_file, bootstyle="secondary")
        btn_browse.pack(side=tk.RIGHT, padx=(5, 0))
        ToolTip(btn_browse, text=self.tr("browse"), padding=3)

        lbt_output = tk.Label(lf_files, text=self.tr("dest_file"))
        lbt_output.pack(anchor=tk.W)
      
        frame_output = ttk.Frame(lf_files)
        frame_output.pack(fill=tk.X)
        self.entry_file_output = ttk.Entry(frame_output)
        self.entry_file_output.pack(side=tk.LEFT, fill=tk.X, expand=True)
        btn_save = ttk.Button(frame_output, text="💾", command=self.browse_output_file, bootstyle="secondary")
        btn_save.pack(side=tk.RIGHT, padx=(5, 0))
        ToolTip(btn_save, text=self.tr("save"), padding=3)

        # Groupe Sécurité
        lf_sec = ttk.Labelframe(self.root, text=self.tr("security"), padding=15, bootstyle="info")
        lf_sec.pack(fill=tk.X, padx=20, pady=10)

        ttk.Label(lf_sec, text=self.tr("pwd")).pack(anchor=tk.W)
        
        frame_pwd = ttk.Frame(lf_sec)
        frame_pwd.pack(fill=tk.X, pady=(0, 5))
        
        self.entry_pwd = ttk.Entry(frame_pwd, show="•")
        self.entry_pwd.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.btn_show_pwd = ttk.Button(frame_pwd, text="👁", width=4, bootstyle="secondary-outline", command=self.toggle_password_visibility)
        self.btn_show_pwd.pack(side=tk.RIGHT, padx=(5, 0))
        ToolTip(self.btn_show_pwd, text=self.tr("show_pwd"), padding=3)

        btn_gen = ttk.Button(frame_pwd, text="🎲", width=4, bootstyle="info-outline", command=self.generate_password)
        btn_gen.pack(side=tk.RIGHT, padx=(5, 0))
        ToolTip(btn_gen, text=self.tr("gen_pwd"), padding=3)

        # Option de suppression sécurisée (uniquement en mode chiffrement)
        if self.mode == "encrypt":
            self.var_secure_delete = tk.BooleanVar()
            ttk.Checkbutton(lf_sec, text=self.tr("secure_del"), variable=self.var_secure_delete, bootstyle="round-toggle").pack(anchor=tk.W, pady=5)

        # Boutons d'action
        frame_actions = ttk.Frame(self.root)
        frame_actions.pack(pady=20)

        if self.mode == "encrypt":
            self.btn_encrypt = ttk.Button(frame_actions, text=f"🔒 {self.tr('start_enc')}", 
                                         bootstyle="danger", width=25, command=self.do_encrypt, state=tk.DISABLED)
            self.btn_encrypt.pack(side=tk.LEFT, padx=10)
            ToolTip(self.btn_encrypt, text=self.tr("start_enc"), padding=3)
            self.btn_decrypt = None
            self.btn_verify = None
        else:
            self.btn_decrypt = ttk.Button(frame_actions, text=f"🔓 {self.tr('start_dec')}", 
                                         bootstyle="success", width=25, command=self.do_decrypt, state=tk.DISABLED)
            self.btn_decrypt.pack(side=tk.LEFT, padx=10)
            ToolTip(self.btn_decrypt, text=self.tr("start_dec"), padding=3)
            
            self.btn_verify = ttk.Button(frame_actions, text=f"🔍 {self.tr('verify')}", 
                                         bootstyle="info-outline", width=12, command=self.do_verify, state=tk.DISABLED)
            self.btn_verify.pack(side=tk.LEFT, padx=10)
            ToolTip(self.btn_verify, text=self.tr("verify"), padding=3)
            self.btn_encrypt = None

        btn_cancel = ttk.Button(frame_actions, text=self.tr("back"), width=10, bootstyle="secondary-outline", command=self.show_welcome_screen)
        btn_cancel.pack(side=tk.LEFT, padx=10)
        ToolTip(btn_cancel, text=self.tr("back"), padding=3)

        btn_reset = ttk.Button(frame_actions, text=self.tr("reset"), width=12, bootstyle="warning-outline", command=self.reset_fields)
        btn_reset.pack(side=tk.LEFT, padx=10)
        ToolTip(btn_reset, text=self.tr("reset"), padding=3)

        # Barre de progression
        frame_prog = ttk.Frame(self.root)
        frame_prog.pack(pady=(0, 10), padx=20, fill=tk.X)
        
        self.progress = ttk.Progressbar(frame_prog, orient="horizontal", mode="determinate", bootstyle="striped")
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.lbl_progress = ttk.Label(frame_prog, text="0 %", width=5, anchor="e")
        self.lbl_progress.pack(side=tk.LEFT, padx=(10, 0))

    def generate_password(self):
        """Génère un mot de passe fort et l'affiche."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        pwd = ''.join(secrets.choice(alphabet) for _ in range(20))
        self.entry_pwd.delete(0, tk.END)
        self.entry_pwd.insert(0, pwd)
        if self.entry_pwd.cget("show") == "•":
            self.toggle_password_visibility()

    def toggle_password_visibility(self):
        if self.entry_pwd.cget("show") == "•":
            self.entry_pwd.config(show="")
            self.btn_show_pwd.config(bootstyle="warning-outline") # Change la couleur quand visible
        else:
            self.entry_pwd.config(show="•")
            self.btn_show_pwd.config(bootstyle="secondary-outline")

    def reset_fields(self):
        self.file_var.set("") # Vide le champ et met à jour l'état des boutons
        self.entry_file_output.delete(0, tk.END)
        self.entry_pwd.delete(0, tk.END)
        self.progress["value"] = 0
        self.lbl_progress.config(text="0 %")
        self.toggle_password_visibility()
       
        if hasattr(self, 'var_secure_delete'):
            self.var_secure_delete.set(False)

    def toggle_buttons(self, *args):
        state = tk.NORMAL if self.file_var.get().strip() else tk.DISABLED
        if self.btn_encrypt: self.btn_encrypt.config(state=state)
        if self.btn_decrypt: self.btn_decrypt.config(state=state)
        if self.btn_verify: self.btn_verify.config(state=state)

    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Sélectionnez un fichier",
            filetypes=[("Fichiers texte", "*.txt",), 
                    ("Tous les fichiers", "*.*")],
            initialdir=os.path.join(os.path.expanduser("~"), "Desktop")
        )
        if filename:
            self.file_var.set(filename)
            
    def browse_output_file(self):
        # En chiffrement on propose .enc, en déchiffrement on laisse libre
        ext = ".enc" if self.mode == "encrypt" else ""
        
        # Pré-remplir le nom du fichier
        initial_name = ""
        input_path = self.entry_file.get()
        if input_path:
            base = os.path.basename(input_path)
            if self.mode == "decrypt" and base.lower().endswith(".enc"):
                initial_name = base[:-4]
            elif self.mode == "encrypt":
                initial_name = base + ".enc"

        filename = filedialog.asksaveasfilename(
            title="Enregistrer le fichier sous",
            defaultextension=ext,
            initialfile=initial_name,
            # Bureau par défaut
            initialdir=os.path.join(os.path.expanduser("~"), "Desktop")
        )
        # Vérifiez si l'utilisateur a sélectionné un fichier ou a annulé la boîte de dialogue.
        if not filename:
            messagebox.showinfo("Annulation","Opération de sauvegarde annulée par l'utilisateur.")
            return
        
        self.entry_file_output.delete(0, tk.END)
        self.entry_file_output.insert(0, filename)
        
    def get_paths(self, is_encrypting: bool) -> tuple:
        input_path = self.entry_file.get()
        password = self.entry_pwd.get()
        output_path_manual = self.entry_file_output.get()


        if not os.path.exists(input_path):
            messagebox.showerror(self.tr("error"), self.tr("err_file"))
            return None, None, None
        if not password:
            messagebox.showerror(self.tr("error"), self.tr("err_pwd"))
            return None, None, None

        if output_path_manual.strip():
            output_path = output_path_manual
        elif is_encrypting:
            output_path = input_path + ".enc"
        else:
            # Si le fichier finit par .enc, on l'enlève, sinon on ajoute .dec
            if input_path.lower().endswith(".enc"):
                output_path = input_path[:-4]
            else:
                output_path = input_path + ".dec"
            
            # Éviter d'écraser le fichier original s'il existe déjà
            if os.path.exists(output_path):
                base, ext = os.path.splitext(output_path)
                output_path = f"{base}_restored{ext}"

        return input_path, output_path, password

    def update_progress(self, current: int, total: int) -> None:
        self.progress["maximum"] = total
        self.progress["value"] = current
        
        if total > 0:
            percent = int((current / total) * 100)
            self.lbl_progress.config(text=f"{percent} %")
            
        self.root.update() # Force la mise à jour de l'interface

    def log_operation(self, action: str, filename: str, status: str, details: str = ""):
        """Enregistre l'opération dans un fichier journal."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {action} : {filename} | {status}"
        if details:
            log_entry += f" ({details})"
        
        log_path = get_writable_path("historique_crypto.log")
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(log_entry + "\n")
        except Exception:
            pass # Ignorer les erreurs d'écriture de log

    def do_encrypt(self):
        inp, out, pwd = self.get_paths(is_encrypting=True)
       
        if not inp or not out: return

        if inp.lower().endswith(".enc"):
            messagebox.showerror("Action impossible", "Le fichier sélectionné est déjà chiffré (.enc).\nIl est inutile de le chiffrer une seconde fois.")
            return

        # Vérification de l'écrasement côté UI
        if os.path.exists(out):
            if not messagebox.askyesno(self.tr("warning"), self.tr("confirm_overwrite").format(file=out)):
                return

        try:
            # On appelle la logique avec overwrite=True car l'utilisateur a déjà confirmé
            encrypt_logic(inp, out, pwd, callback=self.update_progress, overwrite=True, lang=self.current_lang)
            
            self.reset_fields()
            
            msg = f"Fichier chiffré créé :\n{os.path.basename(out)}"
            
            if hasattr(self, 'var_secure_delete') and self.var_secure_delete.get():
                try:
                    secure_delete(inp)
                    msg += "\n\nLe fichier original a été supprimé de manière sécurisée."
                except Exception as del_err:
                    msg += f"\n\nATTENTION: Échec de la suppression sécurisée :\n{del_err}"
            
            self.log_operation("Chiffrement", os.path.basename(inp), "Succès")
            messagebox.showinfo("Succès", msg)

        except Exception as e:
            self.log_operation("Chiffrement", os.path.basename(inp), "Erreur", str(e))
            messagebox.showerror("Erreur", str(e))
            return

    def do_decrypt(self):
        inp, out, pwd = self.get_paths(is_encrypting=False)
        
        if not inp or not out: return
        
        # Vérification de l'écrasement côté UI
        if os.path.exists(out):
            if not messagebox.askyesno(self.tr("warning"), self.tr("confirm_overwrite").format(file=out)):
                return

        try:
            decrypt_logic(inp, out, pwd, callback=self.update_progress, overwrite=True, lang=self.current_lang)
            self.reset_fields()
         
            self.log_operation("Déchiffrement", os.path.basename(inp), "Succès")
            messagebox.showinfo("Succès", f"Fichier restauré :\n{os.path.basename(out)}")
        except InvalidTag:
            if os.path.exists(out): os.remove(out) # Supprime le fichier corrompu
            self.log_operation("Déchiffrement", os.path.basename(inp), "Échec", "Mot de passe incorrect")
            messagebox.showerror("Échec", "Mot de passe incorrect ou fichier corrompu.")
        except zlib.error:
            if os.path.exists(out): os.remove(out)
            self.log_operation("Déchiffrement", os.path.basename(inp), "Échec", "Erreur décompression (Mdp incorrect ?)")
            messagebox.showerror("Échec", "Mot de passe incorrect.\n\nLe déchiffrement a produit des données incohérentes qui ne peuvent pas être décompressées.")
        except Exception as e:
            if os.path.exists(out): os.remove(out)
            self.log_operation("Déchiffrement", os.path.basename(inp), "Erreur", str(e))
            messagebox.showerror("Erreur", str(e))

    def do_verify(self):
        inp = self.entry_file.get()
        pwd = self.entry_pwd.get()
        
        if not inp: return
        if not pwd:
            messagebox.showerror("Erreur", "Le mot de passe est obligatoire.")
            return

        try:
            if verify_integrity_logic(inp, pwd, callback=self.update_progress, lang=self.current_lang):
                self.progress["value"] = 0
                self.lbl_progress.config(text="0 %")
                self.log_operation("Vérification", os.path.basename(inp), "Succès")
                messagebox.showinfo("Intégrité Valide", "✅ Le fichier est intègre.\nLe mot de passe est correct et les données n'ont pas été altérées.")
        except InvalidTag:
            self.log_operation("Vérification", os.path.basename(inp), "Échec", "Signature invalide")
            messagebox.showerror("Échec Intégrité", "❌ ÉCHEC DE VÉRIFICATION\n\nLe mot de passe est incorrect OU le fichier a été modifié/corrompu.")
        except Exception as e:
            self.log_operation("Vérification", os.path.basename(inp), "Erreur", str(e))
            messagebox.showerror("Erreur", str(e))

if __name__ == "__main__": # pragma: no cover
    # Vérification de la version de Python (3.8 minimum recommandé)
    if sys.version_info < (3, 8):
        root = tk.Tk()
        root.withdraw() # Cache la fenêtre principale vide
        messagebox.showerror("Version incompatible", f"Ce programme nécessite Python 3.8 ou supérieur.\nVotre version actuelle : {sys.version.split()[0]}")
        root.destroy()
        sys.exit(1)

    # Utilisation de ttkbootstrap Window au lieu de tk.Tk
    root = ttk.Window(themename="superhero") 
    root.withdraw() # Masquer la fenêtre temporairement pour éviter l'effet de scintillement
    app = CryptoApp(root)
    root.deiconify() # Afficher la fenêtre une fois l'interface prête
    root.mainloop()
