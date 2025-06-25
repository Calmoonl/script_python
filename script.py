import argparse
from prettytable import from_csv
import csv
import requests
import logging
import datetime
from datetime import timedelta
import ssl
import socket
from urllib.parse import urlparse
import configparser

# Import de la configuration
config = configparser.ConfigParser()
config.read('settings.conf')

# Configurations des arguments
parser = argparse.ArgumentParser()
parser.add_argument("-a", "--add",nargs=2)
parser.add_argument("-r", "--remove",nargs=1)
parser.add_argument("-l", "--list",action="store_true")
parser.add_argument("-c", "--check",action="store_true")
parser.add_argument("-e", "--export",nargs=1)
args = parser.parse_args()

# Création / configuration du logger
logger = logging.getLogger(__name__)
logging.basicConfig(filename='./log.txt', level=logging.INFO)

# Dates timestamp
now = datetime.datetime.now()
dt = now.strftime('%Y-%m-%d %H:%M:%S')

# Delta ssl à configurer
delta_ssl_days = int(config['settings']['delta_ssl_days'])
delta_ssl = timedelta(days=delta_ssl_days)

# Fonction qui récupére les certificats SSL
def get_cert_expiry(url):
    # Datetime local pour comparaison
    dt = datetime.datetime.now()
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443

    context = ssl.create_default_context()
    try :
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if dt < expiry_date :
                    return True,expiry_date
                else : 
                    return False,expiry_date
    except Exception as e:
        return False, f"Erreur SSL: {e}"

# Ajouter un site dans le fichier csv
if args.add:
    print("Ajout d'un site")
    # Récupération nom et url du site
    nom = args.add[0]
    url = args.add[1]
    champs = [nom,url]
    print(nom,url)
    # Ajout dans le fichier sites.csv du nouveau site
    with open('csv/sites.csv','a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(champs)

# Retirer un site dans le fichier csv
if args.remove: 
    print("Suppression d'un site")
    liste_site = []
    # Récupération nom à retirer
    nom_supp = args.remove[0]
    # Lire tout le fichier et ne garder que les lignes n'étant pas le site à retirer 
    with open('csv/sites.csv','r', newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        lignes = [ligne for ligne in reader if ligne and ligne[0] != nom_supp]
    # Réécrire le fichier sites sans le site retiré
    with open('csv/sites.csv', 'w', newline='', encoding='utf-8') as fichier:
        writer = csv.writer(fichier)
        writer.writerows(lignes)

# Visionner la liste des sites
if args.list:
    print("Affichage de la liste des sites")
    # Lecture et affichage des sites
    with open('csv/sites.csv','r', newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader :
            print(row)

# Vérifier l'éta des site de la liste
if args.check:
    print("Check des sites")
    # Chemin du fichier résultats
    fichier_res = now.strftime('csv/resultats/%Y-%m-%d-%H-%M-%S.csv')
    # Récupération des urls
    with open('csv/sites.csv','r', newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        urls = [row[1] for row in reader]
    # Création du fichier résultat et de son entête
    with open(fichier_res, 'w', newline='', encoding='utf-8') as result_file:
        writer = csv.writer(result_file)
        writer.writerow(['Date', 'URL', 'Status Code', 'Status','Certificat SSL'])
    
    # Check des URLS
    for url in urls :
        # Vérification SSL
        valide_cert,date_cert = get_cert_expiry(url)
        # Création du message SSL
        if valide_cert : 
            message_ssl = f"Certificat valide jusqu'au {date_cert}"
        else : 
            message_ssl = f"Certificat expiré le {date_cert}"
        
        # Nouveau timestamp local pour calculs
        timestamp = datetime.datetime.now()

        # Requête GET vers les urls du fichier
        requete = requests.get(url)

        # Si les codes de status sont entre 200 et 299 (réponse HTTP service valide)
        if requete.status_code in range(200,299):
            # Si le certificat n'expire pas dans delta_ssl --> logs normaux
            if date_cert - timestamp > delta_ssl :
                logger.info(f'{dt};{url};{requete.status_code};UP;{message_ssl}')
            else : 
            # Sinon ajout d'un statut WARNING_SSL
                logger.info(f'{dt};{url};{requete.status_code};UP;{message_ssl}',extra={"status": "WARNING_SSL"})

            # Écriture dans le fichier résultat
            with open(fichier_res, 'a', newline='', encoding='utf-8') as result_file:
                writer = csv.writer(result_file)
                writer.writerow([dt,url,requete.status_code,"UP",message_ssl])

        # Sinon (réponse HTTP service invalide)
        else : 
            # Si le certificat n'expire pas dans delta_ssl --> logs normaux
            if date_cert - timestamp > delta_ssl :
                logger.warning(f'{dt};{url};{requete.status_code};DOWN;{message_ssl}')
            # Sinon ajout d'un statut WARNING_SSL
            else :
                logger.info(f'{dt};{url};{requete.status_code};UP;{message_ssl}',extra={"status": "WARNING_SSL"})

            # Écriture dans le fichier résultat
            with open(fichier_res, 'a', newline='', encoding='utf-8') as result_file:
                writer = csv.writer(result_file)
                writer.writerow([dt,url,requete.status_code,"DOWN",message_ssl])

if args.export:
    print("Export des résultats")
    # Récupération et nettoyage de l'URL pour créato  fichier
    url = args.export[0]
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    domain_name = domain.split('.')[0]
    resultats = []
    fichier_exp = f'csv/exports/{domain_name}.csv'
    # Lecture des logs pour retrouver les lignes concernant l'URL
    with open('log.txt', 'r', encoding='utf-8') as file:
        reader = csv.reader(file, delimiter=';')
        for row in reader:
            if url in row:
                resultats.append(row)

    # Écriture/réécriture dans un fichier ayant le nom de l'url dans csv/exports
    with open(fichier_exp, 'w', newline='', encoding='utf-8') as result_file:
        writer = csv.writer(result_file)
        for resultat in resultats :
            writer.writerow(resultat)

# Si aucun arguent donné : 
if not (args.add or args.remove or args.list or args.check  or args.export):
    print("Aucune option spécifiée")
