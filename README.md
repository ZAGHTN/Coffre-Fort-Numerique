# Coffre-fort Numérique

![CI Status](https://github.com/ZAGHTN/Coffre-Fort-Numerique/actions/workflows/tests.yml/badge.svg)
[![Codecov](https://img.shields.io/codecov/c/github/ZAGHTN/Coffre-Fort-Numerique?logo=codecov&logoColor=white)](https://codecov.io/gh/ZAGHTN/Coffre-Fort-Numerique)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Une application de bureau sécurisée et moderne pour chiffrer, déchiffrer et protéger vos fichiers sensibles. Développée en Python avec une interface graphique intuitive.

## 🛡️ Fonctionnalités

* **Chiffrement Fort** : Utilise l'algorithme **AES-256** en mode **GCM** (Galois/Counter Mode) pour garantir la confidentialité et l'intégrité des données.
* **Dérivation de Clé Robuste** : Les mots de passe sont renforcés par **PBKDF2-HMAC-SHA256** avec 600 000 itérations et un sel (salt) unique par fichier.
* **Compression** : Les fichiers sont compressés (zlib) avant d'être chiffrés pour réduire leur taille.
* **Suppression Sécurisée** : Option pour écraser le fichier original avec des données aléatoires avant suppression (Secure Delete).
* **Vérification d'Intégrité** : Permet de vérifier si un fichier chiffré est corrompu ou si le mot de passe est correct sans avoir à le déchiffrer entièrement sur le disque.
* **Interface Moderne** : GUI basée sur `ttkbootstrap` avec support des thèmes clair et sombre.
* **Gestion de la Mémoire** : Traitement par blocs (streaming) pour gérer de gros fichiers sans saturer la RAM.

## 🚀 Installation

### Prérequis

* Python 3.8 ou supérieur.

### Étapes

1. Clonez ce dépôt ou téléchargez les fichiers.
2. Installez les dépendances nécessaires via `pip` :

```bash
pip install -r requirements.txt
```

*Le fichier `requirements.txt` contient :*

* `cryptography`
* `ttkbootstrap`

## 💻 Utilisation

Lancez l'application avec la commande suivante :

```bash
python crypto_gui.py
```

1. **Chiffrer** : Sélectionnez un fichier, entrez un mot de passe (ou générez-en un), et cliquez sur "Lancer le chiffrement".
2. **Déchiffrer** : Sélectionnez un fichier `.enc`, entrez le mot de passe correspondant pour restaurer le fichier original.
3. **Vérifier** : Utilisez le bouton "Vérifier" en mode déchiffrement pour tester l'intégrité d'une archive.

## 🔒 Détails Techniques de Sécurité

| Composant | Spécification |
| :--- | :--- |
| **Algorithme** | AES-256-GCM |
| **KDF** | PBKDF2-HMAC-SHA256 |
| **Itérations KDF** | 600 000 (Recommandation OWASP) |
| **Taille du Sel** | 16 octets (Aléatoire par fichier) |
| **Taille du IV** | 12 octets (Aléatoire par fichier) |
| **Tag d'auth** | 16 octets |

## 🤝 Contribuer

Les contributions sont les bienvenues ! Veuillez consulter le fichier CONTRIBUTING.md pour connaître les règles détaillées et la procédure à suivre.

## 📝 Auteur

Zaghdoudi Chokri

---
*Note : Ce logiciel est fourni "tel quel", sans garantie d'aucune sorte. Soyez prudent avec vos mots de passe : s'ils sont perdus, les fichiers chiffrés seront irrécupérables.*
