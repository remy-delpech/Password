import re
import hashlib
import json

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

def add_password(password_dict, website):
    # Demande à l'utilisateur de choisir un mot de passe et l'ajoute à la liste des mots de passe.
    while True:
        password = input("Entrez un mot de passe : ")
        if is_valid_password(password):
            hashed_password = encrypt_password(password)
            if hashed_password in password_dict.values():
                print("Ce mot de passe est déjà utilisé pour un autre site web. Veuillez en choisir un nouveau.\n")
            else:
                password_dict[website] = hashed_password
                print(f"Le mot de passe pour {website} a été ajouté avec succès.")
                break
        else:
            print("Veuillez choisir un nouveau mot de passe.\n")
    
    # Écrit les mots de passe dans le fichier JSON.
    with open("passwords.json", "w") as f:
        json.dump(password_dict, f)

def display_passwords(password_dict):
    # Affiche la liste des sites web avec leur mot de passe.
    for website, password in password_dict.items():
        print(f"{website} : {password}")

# Charge les mots de passe à partir du fichier JSON.
try:
    with open("passwords.json", "r") as f:
        password_dict = json.load(f)
except FileNotFoundError:
    password_dict = {}

# Demande à l'utilisateur de choisir une action (ajouter un mot de passe ou afficher la liste des mots de passe).
while True:
    choice = input("Que voulez-vous faire ?\n1. Ajouter un mot de passe\n2. Afficher les mots de passe\n")
    if choice == "1":
        website = input("Entrez le nom du site web : ")
        add_password(password_dict, website)
        break
    elif choice == "2":
        display_passwords(password_dict)
        break
    else:
        print("Choix invalide, veuillez choisir 1 ou 2.\n")