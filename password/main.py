import re
import hashlib

def is_valid_password(password):
    # Vérifie si le mot de passe respecte toutes les exigences de sécurité.
    if len(password) < 8:
        print("Le mot de passe doit contenir au moins 8 caractères.")
        return False
    elif not re.search("[a-z]", password):
        print("Le mot de passe doit contenir au moins une lettre minuscule.")
        return False
    elif not re.search("[A-Z]", password):
        print("Le mot de passe doit contenir au moins une lettre majuscule.")
        return False
    elif not re.search("[0-9]", password):
        print("Le mot de passe doit contenir au moins un chiffre.")
        return False
    elif not re.search("[!@#$%^&*()_+-={}|\\:;\"'<,>.?/]", password):
        print("Le mot de passe doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
        return False
    else:
        return True

def encrypt_password(password):
    # Utilise l'algorithme SHA-256 pour crypter le mot de passe.
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

# Demande à l'utilisateur de choisir un mot de passe jusqu'à ce qu'il en choisisse un qui soit valide.
while True:
    password = input("Entrez un mot de passe : ")
    if is_valid_password(password):
        hashed_password = encrypt_password(password)
        print("Le mot de passe est valide et a été crypté avec l'algorithme SHA-256 : ", hashed_password)
        break
    else:
        print("Veuillez choisir un nouveau mot de passe.\n")