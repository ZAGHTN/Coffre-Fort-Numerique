# Guide de Contribution

Merci de l'intérêt que vous portez à ce projet ! Nous apprécions toutes les contributions, qu'il s'agisse de signaler un bug, de proposer une fonctionnalité ou de soumettre du code.

## 📋 Code de Conduite

Ce projet se veut un environnement accueillant. Soyez respectueux et courtois envers les autres contributeurs.

## 🐛 Signaler un Bug

Si vous trouvez un bug, merci d'ouvrir une "Issue" sur GitHub en incluant :

1. Une description claire du problème.
2. Les étapes pour reproduire le bug.
3. Votre environnement (Système d'exploitation, version Python).

## 💻 Développement Local

### Installation

1. **Forkez** le dépôt sur GitHub.
2. Clonez votre fork localement :

    ```bash
    git clone https://github.com/VOTRE_USERNAME/Coffre-Fort-Numerique.git
    cd Coffre-Fort-Numerique
    ```

3. Installez les dépendances :

    ```bash
    pip install -r requirements.txt
    ```

### Tests

Avant de soumettre vos modifications, assurez-vous que tous les tests passent :

```bash
python -m unittest test_crypto.py
```

## 🔄 Soumettre une Pull Request (PR)

1. Créez une nouvelle branche pour votre travail : `git checkout -b feature/ma-nouvelle-fonctionnalite`
2. Faites vos modifications et commitez-les avec un message clair.
3. Poussez vers votre fork : `git push origin feature/ma-nouvelle-fonctionnalite`
4. Ouvrez une Pull Request vers la branche `main` du dépôt original.

Merci de votre aide !
