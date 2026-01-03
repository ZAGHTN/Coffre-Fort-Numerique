import unittest
import os
import zlib
from cryptography.exceptions import InvalidTag
# On importe les fonctions logiques de votre application
from crypto_gui import encrypt_logic, decrypt_logic, verify_integrity_logic

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
        success = encrypt_logic(self.input_file, self.enc_file, self.password)
        self.assertTrue(success, "Le chiffrement a échoué")
        self.assertTrue(os.path.exists(self.enc_file), "Le fichier chiffré n'a pas été créé")
        
        # 2. Déchiffrement
        success = decrypt_logic(self.enc_file, self.dec_file, self.password)
        self.assertTrue(success, "Le déchiffrement a échoué")
        self.assertTrue(os.path.exists(self.dec_file), "Le fichier restauré n'a pas été créé")
        
        # 3. Vérification du contenu binaire
        with open(self.input_file, "rb") as f1, open(self.dec_file, "rb") as f2:
            self.assertEqual(f1.read(), f2.read(), "Le contenu déchiffré ne correspond pas à l'original !")

    def test_wrong_password(self):
        """Test : Un mauvais mot de passe doit lever une erreur (InvalidTag)"""
        encrypt_logic(self.input_file, self.enc_file, self.password)
        
        # On s'attend à ce que decrypt_logic lève une exception InvalidTag
        # Avec la compression, zlib échoue souvent avant la vérification du tag si le mot de passe est faux
        with self.assertRaises((InvalidTag, zlib.error)):
            decrypt_logic(self.enc_file, self.dec_file, "MauvaisMotDePasse")

    def test_integrity_check(self):
        """Test : La vérification d'intégrité doit fonctionner"""
        encrypt_logic(self.input_file, self.enc_file, self.password)
        
        self.assertTrue(verify_integrity_logic(self.enc_file, self.password))

if __name__ == '__main__':
    unittest.main()