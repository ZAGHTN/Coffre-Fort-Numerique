import os
import shutil
import zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- CONSTANTES DE SÉCURITÉ ---
TAG_SIZE = 16   # Taille du tag d'authentification
SALT_SIZE = 16  # Taille du sel pour le mot de passe
CHUNK_SIZE = 64 * 1024 # Lecture par blocs de 64 Ko pour la barre de progression

# --- TRADUCTIONS ---
TRANSLATIONS = {
    "fr": {
        "title": "Coffre-fort Numérique",
        "welcome": "Bienvenue dans le Coffre-fort",
        "action_prompt": "Que souhaitez-vous faire ?",
        "encrypt": "Chiffrer",
        "decrypt": "Déchiffrer",
        "verify": "Vérifier",
        "quit": "Quitter",
        "view": "Affichage",
        "dark": "Thème Sombre",
        "light": "Thème Clair",
        "help": "Aide",
        "about": "À propos",
        "update": "Vérifier les mises à jour",
        "file": "Fichier",
        "main_menu": "Menu Principal",
        "history": "Voir l'historique",
        "lang": "Langue",
        "sel_files": "Sélection des fichiers",
        "src_file": "Fichier source :",
        "dest_file": "Destination (Optionnel) :\nSi ce champ est laissé vide, le résultat sera enregistré dans le dossier de l'application.",
        "security": "Sécurité",
        "pwd": "Mot de passe :",
        "secure_del": "Supprimer le fichier original (Secure Delete)",
        "start_enc": "LANCER LE CHIFFREMENT",
        "start_dec": "LANCER LE DÉCHIFFREMENT",
        "back": "Retour",
        "reset": "Réinitialiser",
        "mode_enc": "🔒 Mode Chiffrement",
        "mode_dec": "🔓 Mode Déchiffrement",
        "err_file": "Le fichier d'entrée n'existe pas.",
        "err_pwd": "Le mot de passe est obligatoire.",
        "success": "Succès",
        "error": "Erreur",
        "browse": "Sélectionner un fichier",
        "save": "Choisir où sauvegarder",
        "show_pwd": "Afficher/Masquer le mot de passe",
        "gen_pwd": "Générer un mot de passe aléatoire",
        "about_msg": "Coffre-fort numérique, réalisé avec Python\nVersion : {version}\nAuteur : {author}\n\nSécurité : AES-256 GCM + PBKDF2",
        "hist_title": "Historique des opérations",
        "hist_clear": "🗑 Effacer l'historique",
        "confirm_overwrite": "Le fichier de sortie existe déjà :\n{file}\nVoulez-vous l'écraser ?",
        "warning": "Attention",
        "hist_cleared": "L'historique a été effacé avec succès.",
        "confirm_clear": "Voulez-vous vraiment effacer tout l'historique ?"
    },
    "en": {
        "title": "Digital Safe",
        "welcome": "Welcome to the Digital Safe",
        "action_prompt": "What would you like to do?",
        "encrypt": "Encrypt",
        "decrypt": "Decrypt",
        "verify": "Verify",
        "quit": "Quit",
        "view": "View",
        "dark": "Dark Theme",
        "light": "Light Theme",
        "help": "Help",
        "about": "About",
        "update": "Check for updates",
        "file": "File",
        "main_menu": "Main Menu",
        "history": "View History",
        "lang": "Language",
        "sel_files": "File Selection",
        "src_file": "Source File:",
        "dest_file": "Destination (Optional):\nIf left empty, result will be saved in the application folder.",
        "security": "Security",
        "pwd": "Password:",
        "secure_del": "Delete original file (Secure Delete)",
        "start_enc": "START ENCRYPTION",
        "start_dec": "START DECRYPTION",
        "back": "Back",
        "reset": "Reset",
        "mode_enc": "🔒 Encryption Mode",
        "mode_dec": "🔓 Decryption Mode",
        "err_file": "Input file does not exist.",
        "err_pwd": "Password is required.",
        "success": "Success",
        "error": "Error",
        "browse": "Select a file",
        "save": "Choose where to save",
        "show_pwd": "Show/Hide password",
        "gen_pwd": "Generate random password",
        "about_msg": "Digital Safe, made with Python\nVersion: {version}\nAuthor: {author}\n\nSecurity: AES-256 GCM + PBKDF2",
        "hist_title": "Operation History",
        "hist_clear": "🗑 Clear History",
        "confirm_overwrite": "Output file already exists:\n{file}\nDo you want to overwrite it?",
        "warning": "Warning",
        "hist_cleared": "History cleared successfully.",
        "confirm_clear": "Do you really want to clear the entire history?"
    }
}

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
                  password: str, compress: bool = True, callback: callable = None, overwrite: bool = False, lang: str = "fr") -> bool:
    """Lit, compresse, chiffre et sauvegarde."""
    tr = TRANSLATIONS.get(lang, TRANSLATIONS["fr"])
    # 1. Préparation
    if not os.path.exists(input_file):
        raise FileNotFoundError(tr.get("err_file", "err_file"))
    
    if os.path.exists(output_file) and not overwrite:
        raise FileExistsError(tr.get("confirm_overwrite", "confirm_overwrite").format(file=output_file))

    if not password:
        raise ValueError(tr.get("err_pwd", "err_pwd"))

    # Vérification de l'espace disque disponible
    output_dir = os.path.dirname(os.path.abspath(output_file))
    if os.path.exists(output_dir):
        try:
            _, _, free = shutil.disk_usage(output_dir)
        except OSError:
            free = None # Impossible de vérifier (ex: droits d'accès), on tente quand même

        if free is not None:
            input_size = os.path.getsize(input_file)
            # Estimation pessimiste : taille originale + métadonnées + marge de sécurité (4 Ko)
            estimated_needed = input_size + SALT_SIZE + 12 + TAG_SIZE + 4096
            
            if free < estimated_needed:
                raise OSError(f"Espace disque insuffisant sur la destination.\n\nRequis (est.) : {estimated_needed / (1024**2):.2f} Mo\nDisponible : {free / (1024**2):.2f} Mo")
    
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
                  password: str, callback=None, overwrite: bool = False, lang: str = "fr") -> bool:
    """Lit, déchiffre, décompresse et sauvegarde."""
    tr = TRANSLATIONS.get(lang, TRANSLATIONS["fr"])
    # Vérifier le arguments
    if not os.path.exists(input_file):
        raise FileNotFoundError(tr.get("err_file", "err_file"))
    
    if os.path.exists(output_file) and not overwrite:
        raise FileExistsError(tr.get("confirm_overwrite", "confirm_overwrite").format(file=output_file))

    if not password:
        raise ValueError(tr.get("err_pwd", "err_pwd"))
    
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

def verify_integrity_logic(input_file: str, password: str, callback: callable = None, lang: str = "fr") -> bool:
    """Vérifie l'intégrité du fichier (AES-GCM) sans le déchiffrer sur le disque."""
    tr = TRANSLATIONS.get(lang, TRANSLATIONS["fr"])
    if not os.path.exists(input_file):
        raise FileNotFoundError(tr.get("err_file", "err_file"))
        
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