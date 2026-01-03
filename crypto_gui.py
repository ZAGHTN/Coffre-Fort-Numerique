# -*- coding: utf-8 -*-
import sys
import tkinter as tk
import datetime
import configparser
import shutil
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.widgets import ToolTip
import os
from os import path
import zlib
import string
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- CONSTANTES DE SÉCURITÉ ---
TAG_SIZE = 16   # Taille du tag d'authentification
SALT_SIZE = 16  # Taille du sel pour le mot de passe
CHUNK_SIZE = 64 * 1024 # Lecture par blocs de 64 Ko pour la barre de progression
APP_VERSION = "1.0"
APP_AUTHOR = "Zaghdoudi Chokri"

# --- LOGIQUE DE CHIFFREMENT (Moteur) ---

def secure_delete(file_path: str, passes: int = 1) -> None:
    """Écrase le fichier avec des données aléatoires avant de le supprimer."""
    if not os.path.exists(file_path):
        return
    
    length = os.path.getsize(file_path)
    with open(file_path, "r+b") as f:
        for _ in range(passes):
            f.seek(0)
            remaining = length
            while remaining > 0:
                chunk_size = min(CHUNK_SIZE, remaining)
                f.write(os.urandom(chunk_size))
                remaining -= chunk_size
            f.flush()
            os.fsync(f.fileno()) # Force l'écriture physique sur le disque
    os.remove(file_path)

def derive_key(password: str, salt: bytes) -> bytes:
    """Génère une clé AES-256 à partir du mot de passe."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000, # Recommandation OWASP augmentée pour la sécurité
    )
    return kdf.derive(password.encode())

def encrypt_logic(input_file: str, output_file: str, 
                  password: str, compress: bool = True, callback: callable = None) -> bool:
    """Lit, compresse, chiffre et sauvegarde."""
    # 1. Préparation
    if not os.path.exists(input_file):
        messagebox.showerror("Erreur", "Le fichier d'entrée n'existe pas.")
        return False
    if os.path.exists(output_file):
        if not messagebox.askyesno("Attention", f"Le fichier de sortie existe déjà :\n{output_file}\nVoulez-vous l'écraser ?"):
            return False
    if not password:
        messagebox.showerror("Erreur", "Le mot de passe est obligatoire.")
        return False

    # Vérification de l'espace disque disponible
    try:
        output_dir = os.path.dirname(os.path.abspath(output_file))
        if os.path.exists(output_dir):
            _, _, free = shutil.disk_usage(output_dir)
            input_size = os.path.getsize(input_file)
            # Estimation pessimiste : taille originale + métadonnées + marge de sécurité (4 Ko)
            estimated_needed = input_size + SALT_SIZE + 12 + TAG_SIZE + 4096
            
            if free < estimated_needed:
                messagebox.showerror("Erreur Espace Disque", f"Espace disque insuffisant sur la destination.\n\nRequis (est.) : {estimated_needed / (1024**2):.2f} Mo\nDisponible : {free / (1024**2):.2f} Mo")
                return False
    except OSError:
        pass # Si la vérification échoue (ex: droits d'accès), on tente quand même l'opération
    
    # 2. Chiffrement
    iv = os.urandom(12)
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)

    compressor = zlib.compressobj() if compress else None
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()

    file_size = os.path.getsize(input_file)
    processed = 0

    try:
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            f_out.write(salt + iv)
            
            # Optimisation : Buffer réutilisable pour éviter les allocations répétées
            buf = bytearray(CHUNK_SIZE)
            
            while True:
                n = f_in.readinto(buf) # Remplissage du tampon
                if not n:
                    break
                
                # Vue mémoire sans copie (memoryview)
                chunk = memoryview(buf)[:n]
                
                # Compresser et chiffrer à la volée
                if compressor:
                    data_to_encrypt = compressor.compress(chunk)
                else:
                    data_to_encrypt = chunk
                
                if data_to_encrypt:
                    f_out.write(encryptor.update(data_to_encrypt))
                
                processed += n
                if callback:
                    callback(processed, file_size)

            # Finalisation
            if compressor:
                remaining = compressor.flush()
                if remaining:
                    f_out.write(encryptor.update(remaining))
            
            f_out.write(encryptor.finalize())
            f_out.write(encryptor.tag)
            
    except OSError as e:
        # Gestion spécifique disque plein (Errno 28 / WinError 112)
        if e.errno == 28 or (os.name == 'nt' and getattr(e, 'winerror', 0) == 112):
            if os.path.exists(output_file):
                try:
                    os.remove(output_file)
                except OSError:
                    pass
            raise OSError("Espace disque insuffisant. L'opération a été annulée et le fichier partiel supprimé.")
        raise e
    
    return True

def decrypt_logic(input_file: str, output_file: str, 
                  password: str, callback=None) -> bool:
    """Lit, déchiffre, décompresse et sauvegarde."""
    # Vérifier le arguments
    if not os.path.exists(input_file):
        messagebox.showerror("Erreur", "Le fichier d'entrée n'existe pas.")
        return False
    if os.path.exists(output_file):
        if not messagebox.askyesno("Attention", f"Le fichier de sortie existe déjà :\n{output_file}\nVoulez-vous l'écraser ?"):
            return False
    if not password:
        messagebox.showerror("Erreur", "Le mot de passe est obligatoire.")
        return False
    
    # Vérification taille minimale
    file_size = os.path.getsize(input_file)
    if file_size < SALT_SIZE + 12 + TAG_SIZE:
        raise ValueError("Fichier invalide ou corrompu.")

    with open(input_file, 'rb') as f_in:
        # 1. Lecture des métadonnées
        salt = f_in.read(SALT_SIZE)
        iv = f_in.read(12)
        
        # Récupération du tag à la fin du fichier
        f_in.seek(-TAG_SIZE, 2)
        tag = f_in.read(TAG_SIZE)
        f_in.seek(SALT_SIZE + 12, 0) # Retour au début des données

        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        decompressor = zlib.decompressobj()

        data_end = file_size - TAG_SIZE
        
        with open(output_file, 'wb') as f_out:
            # Optimisation : Buffer réutilisable
            buf = bytearray(CHUNK_SIZE)
            
            while f_in.tell() < data_end:
                chunk_len = min(CHUNK_SIZE, data_end - f_in.tell())
                
                view = memoryview(buf)[:chunk_len]
                n = f_in.readinto(view)
                if not n: break
                
                decrypted = decryptor.update(view[:n])
                f_out.write(decompressor.decompress(decrypted))
                
                if callback:
                    callback(f_in.tell(), file_size)
            
            # Vérification finale (lève InvalidTag si corrompu)
            final_dec = decryptor.finalize()
            f_out.write(decompressor.decompress(final_dec))
            f_out.write(decompressor.flush())
    return True

def verify_integrity_logic(input_file: str, password: str, callback: callable = None) -> bool:
    """Vérifie l'intégrité du fichier (AES-GCM) sans le déchiffrer sur le disque."""
    if not os.path.exists(input_file):
        raise FileNotFoundError("Le fichier n'existe pas.")
        
    file_size = os.path.getsize(input_file)
    if file_size < SALT_SIZE + 12 + TAG_SIZE:
        raise ValueError("Fichier trop petit ou corrompu.")

    with open(input_file, 'rb') as f_in:
        salt = f_in.read(SALT_SIZE)
        iv = f_in.read(12)
        
        f_in.seek(-TAG_SIZE, 2)
        tag = f_in.read(TAG_SIZE)
        f_in.seek(SALT_SIZE + 12, 0)

        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()

        data_end = file_size - TAG_SIZE
        
        while f_in.tell() < data_end:
            chunk_len = min(CHUNK_SIZE, data_end - f_in.tell())
            chunk = f_in.read(chunk_len)
            if not chunk: break
            decryptor.update(chunk)
            if callback:
                callback(f_in.tell(), file_size)
        
        decryptor.finalize() # Lève InvalidTag si échec
    return True

def resource_path(relative_path: str) -> str:
    """Obtient le chemin absolu de la ressource, fonctionne pour dev et PyInstaller."""
    
    return path.abspath(path.join(path.dirname(__file__), relative_path))

# --- INTERFACE GRAPHIQUE (Tkinter) ---

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Coffre-fort Numérique")
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
        self.config_file = "config.ini"
        self.load_config()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.btn_encrypt = None
        self.btn_decrypt = None
        self.btn_verify = None
        self.show_welcome_screen()

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

    def show_welcome_screen(self):
        """Affiche l'écran de sélection du mode."""
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Réinitialiser le menu
        menubar = tk.Menu(self.root)
        exit_menu = tk.Menu(menubar, tearoff=0)
        exit_menu.add_command(label="Quitter", command=self.on_closing)
        menubar.add_cascade(label="Quitter", menu=exit_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Thème Sombre", command=lambda: self.change_theme("superhero"))
        view_menu.add_command(label="Thème Clair", command=lambda: self.change_theme("cosmo"))
        menubar.add_cascade(label="Affichage", menu=view_menu)

        self.root.config(menu=menubar)

        # Centrer la fenêtre d'accueil
        self.center_window(450, 250)
        
        ttk.Label(self.root, text="Bienvenue dans le Coffre-fort", font=("Helvetica", 10, "bold"), bootstyle="info").pack(pady=20, fill=X)
        ttk.Label(self.root, text="Que souhaitez-vous faire ?", font=("Helvetica", 10)).pack(pady=10)
        
        frame_buttons = ttk.Frame(self.root)
        frame_buttons.pack(pady=20)
        
        btn_enc = ttk.Button(frame_buttons, text=" Chiffrer", width=15, bootstyle="danger-outline", command=lambda: self.setup_main_ui("encrypt"))
        btn_enc.pack(side=tk.LEFT, padx=10)
        ToolTip(btn_enc, text="Chiffrer un fichier pour le protéger", padding=3)
        
        btn_dec = ttk.Button(frame_buttons, text="🔓 Déchiffrer", width=15, bootstyle="success-outline", command=lambda: self.setup_main_ui("decrypt"))
        btn_dec.pack(side=tk.LEFT, padx=10)
        ToolTip(btn_dec, text="Restaurer un fichier chiffré", 
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
        
        with open(self.config_file, "w") as f:
            config.write(f)

    def change_theme(self, theme_name):
        """Change le thème de l'interface et sauvegarde."""
        self.current_theme = theme_name
        self.root.style.theme_use(theme_name)
        self.save_config()

    def on_closing(self):
        """Sauvegarde et quitte."""
        self.save_config()
        self.root.destroy()

    def show_about(self):
        """Affiche la fenêtre À propos."""
        messagebox.showinfo("À propos", f"Coffre-fort numérique, réalisé avec Python\nVersion : {APP_VERSION}\nAuteur : {APP_AUTHOR}\n\nSécurité : AES-256 GCM + PBKDF2")

    def check_updates(self):
        """Simule la vérification des mises à jour."""
        messagebox.showinfo("Mise à jour", "Connexion au serveur...\n\nVous utilisez la dernière version disponible.")

    def show_logs(self):
        """Affiche le contenu du fichier journal dans une nouvelle fenêtre."""
        log_file = "historique_crypto.log"
        if not os.path.exists(log_file):
            messagebox.showinfo("Information", "Aucun historique disponible pour le moment.")
            return

        top = ttk.Toplevel(self.root)
        top.title("Historique des opérations")
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
            if messagebox.askyesno("Confirmation", "Voulez-vous vraiment effacer tout l'historique ?"):
                try:
                    open(log_file, 'w').close() # Vider le fichier
                    text_area.configure(state='normal')
                    text_area.delete('1.0', tk.END)
                    text_area.configure(state='disabled')
                    messagebox.showinfo("Succès", "Historique effacé avec succès.")
                except Exception as e:
                    messagebox.showerror("Erreur", f"Impossible d'effacer le fichier : {e}")

        ttk.Button(top, text="🗑 Effacer l'historique", bootstyle="danger-outline", command=clear_history).pack(pady=10)

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
        file_menu.add_command(label="Menu Principal", command=self.show_welcome_screen)
        file_menu.add_command(label="Voir l'historique", command=self.show_logs)
        file_menu.add_separator()
        file_menu.add_command(label="Quitter", command=self.on_closing)
        menubar.add_cascade(label="Fichier", menu=file_menu)

        # Menu Affichage
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Thème Sombre", command=lambda: self.change_theme("superhero"))
        view_menu.add_command(label="Thème Clair", command=lambda: self.change_theme("cosmo"))
        menubar.add_cascade(label="Affichage", menu=view_menu)

        # Menu Aide
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="À propos", command=self.show_about)
        help_menu.add_command(label="Vérifier les mises à jour", command=self.check_updates)
        menubar.add_cascade(label="Aide", menu=help_menu)

        self.root.config(menu=menubar)

        # Zone de sélection de fichier
        style_color = "danger" if self.mode == "encrypt" else "success"
        title_text = "🔒 Mode Chiffrement" if self.mode == "encrypt" else "🔓 Mode Déchiffrement"
        
        ttk.Label(self.root, text=title_text, font=("Helvetica", 14, "bold"), bootstyle=style_color).pack(pady=(15, 10))
        
        # Groupe Fichiers
        lf_files = ttk.Labelframe(self.root, text="Sélection des fichiers", padding=15, bootstyle=style_color)
        lf_files.pack(fill=tk.X, padx=20, pady=5)

        ttk.Label(lf_files, text="Fichier source :").pack(anchor=tk.W)
        frame_input = ttk.Frame(lf_files)
        frame_input.pack(fill=tk.X, pady=(0, 10))
        
        self.file_var = tk.StringVar()
        self.file_var.trace_add("write", self.toggle_buttons)
        self.entry_file = ttk.Entry(frame_input, textvariable=self.file_var)
        self.entry_file.pack(side=tk.LEFT, fill=tk.X, expand=True)
        btn_browse = ttk.Button(frame_input, text="📂", command=self.browse_file, bootstyle="secondary")
        btn_browse.pack(side=tk.RIGHT, padx=(5, 0))
        ToolTip(btn_browse, text="Sélectionner un fichier", padding=3)

        lbt_output = tk.Label(lf_files, text="Destination (Optionnel) :\nSi ce champ est laissé vide, le résultat sera enregistré dans le dossier de l'application.")
        lbt_output.pack(anchor=tk.W)
      
        frame_output = ttk.Frame(lf_files)
        frame_output.pack(fill=tk.X)
        self.entry_file_output = ttk.Entry(frame_output)
        self.entry_file_output.pack(side=tk.LEFT, fill=tk.X, expand=True)
        btn_save = ttk.Button(frame_output, text="💾", command=self.browse_output_file, bootstyle="secondary")
        btn_save.pack(side=tk.RIGHT, padx=(5, 0))
        ToolTip(btn_save, text="Choisir où sauvegarder", padding=3)

        # Groupe Sécurité
        lf_sec = ttk.Labelframe(self.root, text="Sécurité", padding=15, bootstyle="info")
        lf_sec.pack(fill=tk.X, padx=20, pady=10)

        ttk.Label(lf_sec, text="Mot de passe :").pack(anchor=tk.W)
        
        frame_pwd = ttk.Frame(lf_sec)
        frame_pwd.pack(fill=tk.X, pady=(0, 5))
        
        self.entry_pwd = ttk.Entry(frame_pwd, show="•")
        self.entry_pwd.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.btn_show_pwd = ttk.Button(frame_pwd, text="👁", width=4, bootstyle="secondary-outline", command=self.toggle_password_visibility)
        self.btn_show_pwd.pack(side=tk.RIGHT, padx=(5, 0))
        ToolTip(self.btn_show_pwd, text="Afficher/Masquer le mot de passe", padding=3)

        btn_gen = ttk.Button(frame_pwd, text="🎲", width=4, bootstyle="info-outline", command=self.generate_password)
        btn_gen.pack(side=tk.RIGHT, padx=(5, 0))
        ToolTip(btn_gen, text="Générer un mot de passe aléatoire", padding=3)

        # Option de suppression sécurisée (uniquement en mode chiffrement)
        if self.mode == "encrypt":
            self.var_secure_delete = tk.BooleanVar()
            ttk.Checkbutton(lf_sec, text="Supprimer le fichier original (Secure Delete)", variable=self.var_secure_delete, bootstyle="round-toggle").pack(anchor=tk.W, pady=5)

        # Boutons d'action
        frame_actions = ttk.Frame(self.root)
        frame_actions.pack(pady=20)

        if self.mode == "encrypt":
            self.btn_encrypt = ttk.Button(frame_actions, text="🔒 LANCER LE CHIFFREMENT", 
                                         bootstyle="danger", width=25, command=self.do_encrypt, state=tk.DISABLED)
            self.btn_encrypt.pack(side=tk.LEFT, padx=10)
            ToolTip(self.btn_encrypt, text="Démarrer le chiffrement", padding=3)
            self.btn_decrypt = None
            self.btn_verify = None
        else:
            self.btn_decrypt = ttk.Button(frame_actions, text="🔓 LANCER LE DÉCHIFFREMENT", 
                                         bootstyle="success", width=25, command=self.do_decrypt, state=tk.DISABLED)
            self.btn_decrypt.pack(side=tk.LEFT, padx=10)
            ToolTip(self.btn_decrypt, text="Démarrer le déchiffrement", padding=3)
            
            self.btn_verify = ttk.Button(frame_actions, text="🔍 Vérifier", 
                                         bootstyle="info-outline", width=12, command=self.do_verify, state=tk.DISABLED)
            self.btn_verify.pack(side=tk.LEFT, padx=10)
            ToolTip(self.btn_verify, 
                    text="Vérifier l'intégrité sans déchiffrer", padding=3)
            self.btn_encrypt = None

        btn_cancel = ttk.Button(frame_actions, text="Retour", width=10, bootstyle="secondary-outline", command=self.show_welcome_screen)
        btn_cancel.pack(side=tk.LEFT, padx=10)
        ToolTip(btn_cancel, text="Revenir au menu principal", padding=3)

        btn_reset = ttk.Button(frame_actions, text="Réinitialiser", width=12, bootstyle="warning-outline", command=self.reset_fields)
        btn_reset.pack(side=tk.LEFT, padx=10)
        ToolTip(btn_reset, text="Vider tous les champs", padding=3)

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
            messagebox.showerror("Erreur", "Veuillez sélectionner un fichier valide.")
            return None, None, None
        if not password:
            messagebox.showerror("Erreur", "Le mot de passe est obligatoire.")
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
        
        try:
            with open("historique_crypto.log", "a", encoding="utf-8") as f:
                f.write(log_entry + "\n")
        except Exception:
            pass # Ignorer les erreurs d'écriture de log

    def do_encrypt(self):
        inp, out, pwd = self.get_paths(is_encrypting=True)
       
        if not inp or not out: return

        if inp.lower().endswith(".enc"):
            messagebox.showerror("Action impossible", "Le fichier sélectionné est déjà chiffré (.enc).\nIl est inutile de le chiffrer une seconde fois.")
            return

        try:
            if encrypt_logic(inp, out, pwd, callback=self.update_progress):
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
        
        try:
            if not decrypt_logic(inp, out, pwd, callback=self.update_progress):
                return
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
            if verify_integrity_logic(inp, pwd, callback=self.update_progress):
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

if __name__ == "__main__":
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
