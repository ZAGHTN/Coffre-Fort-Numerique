import unittest
import os
import zlib
from unittest.mock import patch
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

if __name__ == '__main__':
    unittest.main()