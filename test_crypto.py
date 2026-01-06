import unittest
import os
import zlib
from unittest.mock import patch, MagicMock
from cryptography.exceptions import InvalidTag
# On importe les fonctions logiques de l'application
from crypto_logic import encrypt_logic, decrypt_logic, verify_integrity_logic, secure_delete

class TestCrypto(unittest.TestCase):
    def setUp(self):
        """Préparation avant chaque test"""
        self.input_file = "test_data.txt"
        self.enc_file = "test_data.txt.enc"
        self.dec_file = "test_data_restored.txt"
        self.password = "SuperSecretPassword123!"
        
        # Créer un fichier de test avec du contenu
        with open(self.input_file, "wb") as f:
            f.write(b"Ceci est un test de chiffrement. " * 100)

        # S'assurer que les fichiers de sortie n'existent pas (pour éviter les popups GUI)
        if os.path.exists(self.enc_file): os.remove(self.enc_file)
        if os.path.exists(self.dec_file): os.remove(self.dec_file)

    def tearDown(self):
        """Nettoyage après chaque test"""
        for f in [self.input_file, self.enc_file, self.dec_file]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except:
                    pass

    def test_encrypt_decrypt_success(self):
        """Test : Chiffrer puis déchiffrer doit redonner le fichier original"""
        # 1. Chiffrement
        success = encrypt_logic(self.input_file, self.enc_file, self.password, overwrite=True)
        self.assertTrue(success, "Le chiffrement a échoué")
        self.assertTrue(os.path.exists(self.enc_file), "Le fichier chiffré n'a pas été créé")
        
        # 2. Déchiffrement
        success = decrypt_logic(self.enc_file, self.dec_file, self.password, overwrite=True)
        self.assertTrue(success, "Le déchiffrement a échoué")
        self.assertTrue(os.path.exists(self.dec_file), "Le fichier restauré n'a pas été créé")
        
        # 3. Vérification du contenu binaire
        with open(self.input_file, "rb") as f1, open(self.dec_file, "rb") as f2:
            self.assertEqual(f1.read(), f2.read(), "Le contenu déchiffré ne correspond pas à l'original !")

    def test_wrong_password(self):
        """Test : Un mauvais mot de passe doit lever une erreur (InvalidTag)"""
        encrypt_logic(self.input_file, self.enc_file, self.password, overwrite=True)
        
        # On s'attend à ce que decrypt_logic lève une exception InvalidTag
        # Avec la compression, zlib échoue souvent avant la vérification du tag si le mot de passe est faux
        with self.assertRaises((InvalidTag, zlib.error)):
            decrypt_logic(self.enc_file, self.dec_file, "MauvaisMotDePasse", overwrite=True)

    def test_overwrite_protection(self):
        """Test : Vérifie que la logique lève une erreur si le fichier existe et overwrite=False"""
        # On crée un fichier "existant"
        with open(self.enc_file, "w") as f:
            f.write("Fichier existant")

        # On s'attend à une erreur FileExistsError
        with self.assertRaises(FileExistsError):
            encrypt_logic(self.input_file, self.enc_file, self.password, overwrite=False)
            
        # Mais cela doit fonctionner si on force l'écrasement
        success = encrypt_logic(self.input_file, self.enc_file, self.password, overwrite=True)
        self.assertTrue(success)

    def test_integrity_check(self):
        """Test : La vérification d'intégrité doit fonctionner"""
        encrypt_logic(self.input_file, self.enc_file, self.password)
        
        self.assertTrue(verify_integrity_logic(self.enc_file, self.password))

    @patch("os.remove")
    def test_secure_delete(self, mock_remove):
        """Test : secure_delete doit écraser le contenu avant suppression"""
        # Création d'un fichier avec contenu connu
        content = b"Donnees confidentielles a detruire" * 10
        with open(self.input_file, "wb") as f:
            f.write(content)
            
        # Appel de secure_delete (avec mock de os.remove pour garder le fichier sur le disque)
        secure_delete(self.input_file)
        
        # Vérification 1 : Le contenu a changé (écrasement)
        with open(self.input_file, "rb") as f:
            new_content = f.read()
            
        self.assertNotEqual(content, new_content, "Le fichier n'a pas été écrasé !")
        self.assertEqual(len(content), len(new_content), "La taille du fichier a changé")
        
        # Vérification 2 : os.remove a bien été appelé à la fin
        mock_remove.assert_called_with(self.input_file)

    # --- EXEMPLE POUR MOCKER LES MESSAGEBOX ---
    # Adaptez le chemin 'crypto_gui.Messagebox' si nécessaire selon vos imports
    @patch('ttkbootstrap.dialogs.Messagebox') 
    def test_mock_messagebox_example(self, mock_mb):
        """
        Test exemple : Vérifie que les popups ne bloquent pas l'exécution.
        Le décorateur @patch remplace Messagebox par un Mock.
        """
        # Ici, on configure le mock pour renvoyer "Oui" (True) si une question est posée
        # ex: Messagebox.askyesno(...) renverra True
        mock_mb.askyesno.return_value = True

        # Si votre fonction 'encrypt_logic' affichait une popup en cas d'erreur :
        # encrypt_logic(..., mauvais_param)
        # mock_mb.show_error.assert_called() # On vérifie que la popup a été "vue"

    def test_callbacks_and_options(self):
        """Test : Callbacks et option de compression (couvre les branches if callback: ...)"""
        # Callback simple pour vérifier qu'il est bien appelé
        progress_called = False
        def cb(current, total):
            nonlocal progress_called
            progress_called = True

        # 1. Encrypt avec compress=False (branche else) et callback
        encrypt_logic(self.input_file, self.enc_file, self.password, compress=False, callback=cb, overwrite=True)
        self.assertTrue(progress_called, "Le callback de chiffrement n'a pas été appelé")
        
        # 2. Decrypt avec callback
        progress_called = False
        decrypt_logic(self.enc_file, self.dec_file, self.password, callback=cb, overwrite=True)
        self.assertTrue(progress_called, "Le callback de déchiffrement n'a pas été appelé")

        # 3. Verify avec callback
        progress_called = False
        verify_integrity_logic(self.enc_file, self.password, callback=cb)
        self.assertTrue(progress_called, "Le callback de vérification n'a pas été appelé")

    def test_input_validation_errors(self):
        """Test : Erreurs de validation (Fichier manquant, mot de passe vide, fichier trop petit)"""
        # Cas : Fichier inexistant
        with self.assertRaises(FileNotFoundError):
            encrypt_logic("fichier_fantome.txt", self.enc_file, self.password)
        with self.assertRaises(FileNotFoundError):
            decrypt_logic("fichier_fantome.txt", self.dec_file, self.password)
        with self.assertRaises(FileNotFoundError):
            verify_integrity_logic("fichier_fantome.txt", self.password)

        # Cas : Mot de passe vide
        with self.assertRaises(ValueError):
            encrypt_logic(self.input_file, self.enc_file, "")
        with self.assertRaises(ValueError):
            decrypt_logic(self.enc_file, self.dec_file, "")

        # Cas : Fichier trop petit (corrompu ou vide)
        tiny_file = "tiny.txt"
        with open(tiny_file, "w") as f: f.write("trop_court")
        try:
            with self.assertRaises(ValueError): # Doit lever "Fichier invalide ou corrompu"
                decrypt_logic(tiny_file, "out.txt", self.password)
            with self.assertRaises(ValueError):
                verify_integrity_logic(tiny_file, self.password)
        finally:
            if os.path.exists(tiny_file): os.remove(tiny_file)

    def test_secure_delete_missing_file(self):
        """Test : secure_delete sur un fichier qui n'existe pas (doit juste retourner)"""
        secure_delete("fichier_qui_nexiste_pas.txt")

    @patch("shutil.disk_usage")
    def test_disk_full_error(self, mock_disk_usage):
        """Test : Erreur d'espace disque insuffisant (simulé)"""
        # Simuler un disque avec seulement 1 octet de libre : (total, used, free)
        mock_disk_usage.return_value = (1000, 999, 1) 
        
        with self.assertRaises(OSError) as cm:
            encrypt_logic(self.input_file, self.enc_file, self.password)
        
        self.assertIn("Espace disque insuffisant", str(cm.exception))

    @patch("os.remove")
    def test_permission_error_simulation(self, mock_remove):
        """Test : Simulation d'une PermissionError avec side_effect"""
        # On configure le mock pour qu'il lève une exception quand il est appelé
        mock_remove.side_effect = PermissionError("Accès refusé : fichier verrouillé par le système")
        
        # secure_delete appelle os.remove, qui va maintenant "exploser" avec l'erreur
        with self.assertRaises(PermissionError):
            secure_delete(self.input_file)

    def test_side_effect_for_file_reading_simulation(self):
        """Démonstration : Simuler la lecture d'un fichier par blocs avec side_effect."""
        
        # 1. Les "morceaux" que la méthode read() simulera retourner.
        # Le dernier est un bytestring vide pour marquer la fin du fichier (EOF).
        chunks_a_lire = [b'premier bloc de donnees', b'deuxieme bloc', b'']

        # 2. On crée un mock de l'objet fichier et on configure sa méthode read().
        # MagicMock simule les méthodes magiques comme __enter__/__exit__ si besoin.
        mock_file = MagicMock()
        mock_file.read.side_effect = chunks_a_lire

        # 3. Code qui utilise cet objet fichier (simule une boucle de lecture).
        donnees_lues = b""
        while True:
            # Chaque appel à mock_file.read() retournera le prochain élément de la liste.
            chunk = mock_file.read(1024) # L'argument (1024) est ignoré par le mock ici.
            if not chunk:
                break
            donnees_lues += chunk

        # 4. Vérifications
        self.assertEqual(donnees_lues, b'premier bloc de donneesdeuxieme bloc')
        self.assertEqual(mock_file.read.call_count, 3, "La méthode read() aurait dû être appelée 3 fois.")

if __name__ == '__main__':
    unittest.main()