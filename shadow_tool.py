'''
Petit script de découverte des mots de passe du fichier shadow par bruteforce.

Syntaxe : sudo python3 shadow_tool.py dictionnaire [shadow_file=/etc/shadow]

- On prépare la liste des utilisateurs dont on cherche le mot de
  passe, en parsant le fichier /etc/shadow.
- On compare chaque ligne du dictionnaire concaténée avec les
  informations précédemment parsées
'''
import crypt
import sys
import os

if len(sys.argv) <= 1:
    print("Syntaxe : \n\tsudo ", sys.argv[0], " dictionnaire.txt")
    sys.exit(1)

# Droits nécessaires pour un accès en lecture au fichier shadow
if os.geteuid() != 0:
    exit("Essayez la commande : \n\tsudo " + ' '.join(sys.argv))


# On parse le fichier shadow et on enregistre les utilisateurs
# ayant un mot de passe dans la variable liste_utilisateurs.
liste_utilisateurs = list()
with open("/etc/shadow" if len(sys.argv) <= 2 else sys.argv[2], "r") as shadow_file:
    shadow = shadow_file.read().splitlines()
    for line in shadow:
        champs = line.split(":")
        mdp = champs[1]
        if len(mdp) > 4:
            hash_id, sel, hash = mdp.split("$")[1:]
            liste_utilisateurs.append({
                "name": champs[0],
                "hash_sel": '$'.join(mdp.split("$")[:3]) + "$",  # $X$sel$
                "hash": mdp,  # $X$sel$hash
            })

# On parcourt le dictionnaire composé de mots de passe et on les testes
# un à un.
with open(sys.argv[1], "r") as dictionnaire:
    for ligne in dictionnaire:
        password = ligne[:-1]  # supprimer retour à la ligne
        for user in liste_utilisateurs:
            if crypt.crypt(password, salt=user["hash_sel"]) == user["hash"]:
                user["password"] = password

# Affichage des résultats
for user in liste_utilisateurs:
    print(user["name"].ljust(20), user["password"] if "password" in user.keys() else "-")
