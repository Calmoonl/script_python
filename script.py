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

parser = argparse.ArgumentParser()
parser.add_argument("-a", "--add",nargs=2)
parser.add_argument("-r", "--remove",nargs=1)
parser.add_argument("-l", "--list",action="store_true")
parser.add_argument("-c", "--check",action="store_true")
parser.add_argument("-e", "--export",nargs=1,action="store_true")
args = parser.parse_args()
logger = logging.getLogger(__name__)

logging.basicConfig(filename='./log.txt', level=logging.INFO)

now = datetime.datetime.now()
dt = now.strftime('%Y-%m-%d %H:%M:%S')

delta_ssl = timedelta(days=15)

# def get_sites() : 
#     with open('csv/sites.csv', newline='', encoding='utf-8') as csvfile:
#         reader = csv.reader(csvfile)
#         liste_site = [row[0] for row in reader]
#     return liste_site

def get_cert_expiry(url):
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443

    dt = datetime.datetime.now()

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
    
if args.add:
    print("Ajout d'un site")
    nom = args.add[0]
    url = args.add[1]
    champs = [nom,url]
    print(nom,url)
    with open('csv/sites.csv','a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(champs)

if args.remove: 
    print("Suppression d'un site")
    liste_site = []
    nom_supp = args.remove[0]
    with open('csv/sites.csv','r', newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        lignes = [ligne for ligne in reader if ligne and ligne[0] != nom_supp]
    
    with open('csv/sites.csv', 'w', newline='', encoding='utf-8') as fichier:
        writer = csv.writer(fichier)
        writer.writerows(lignes)
    
if args.list:
    print("Affichage de la liste des sites")
    with open('csv/sites.csv','r', newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader :
            print(row)

if args.check:
    print("Check des sites")
    fichier_res = now.strftime('csv/resultats/%Y-%m-%d-%H-%M-%S.csv')
    with open('csv/sites.csv','r', newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        urls = [row[1] for row in reader]
    with open(fichier_res, 'w', newline='', encoding='utf-8') as result_file:
        writer = csv.writer(result_file)
        writer.writerow(['Date', 'URL', 'Status Code', 'Status','Certificat SSL'])
    for url in urls :
        valide_cert,date_cert = get_cert_expiry(url)
        if valide_cert : 
            message_ssl = f"Certificat valide jusqu'au {date_cert}"
        else : 
            message_ssl = f"Certificat expiré le {date_cert}"
        timestamp = datetime.datetime.now()
        requete = requests.get(url)

        if requete.status_code in range(200,299):
            if date_cert - timestamp > delta_ssl :
                logger.info(f'{dt};{url};{requete.status_code};UP;{message_ssl}')
            else : 
                logger.info(f'{dt};{url};{requete.status_code};UP;{message_ssl}',extra={"status": "SSL_EXPIRED"})
            with open(fichier_res, 'a', newline='', encoding='utf-8') as result_file:
                writer = csv.writer(result_file)
                writer.writerow([dt,url,requete.status_code,"UP",message_ssl])
        else : 
            if date_cert - timestamp > delta_ssl :
                logger.warning(f'{dt};{url};{requete.status_code};DOWN;{message_ssl}')
            else :
                logger.info(f'{dt};{url};{requete.status_code};UP;{message_ssl}',extra={"status": "SSL_EXPIRED"})
            with open(fichier_res, 'a', newline='', encoding='utf-8') as result_file:
                writer = csv.writer(result_file)
                writer.writerow([dt,url,requete.status_code,"DOWN",message_ssl])

if args.export:
    print("Export des résultats")
    url = args.export[0]
    resultats = []
    fichier_exp = now.strftime('csv/exports/{url}.csv')
    with open('logs.txt', 'r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            if url in row:
                resultats.append(row)
    with open(fichier_res, 'w', newline='', encoding='utf-8') as result_file:
        writer = csv.writer(result_file)
        for resultat in resultats :
            writer.writerow(resultat)

if not (args.add or args.remove or args.list or args.check):
    print("Aucune option spécifiée")


# with open(args.file, "r", encoding='utf-8') as file:
#         reader = csv.reader(file)
#         headers = next(reader)
#         for row in reader:
#             data = dict(zip(headers, row))
#             response = requests.post('https://cplr.oriatec-host.fr/index.php', json=data, headers={'Content-Type': 'application/json'})
#             logs += f"Envoi des informations pour {data['nom']} {data['prenom']} | {data['email']}, {data['telephone']}) - Réponse: {str(response.status_code)}\n"

# myhandlers=[]


#     print("Log : ")
#     with open('arguments/log.txt', "w", encoding='utf-8') as file:
#         file.write(logs)
#     #myhandlers.__add__(file_handler)


#         print("Liste des personnes à ajouter : ")
#     with open(args.file, "r", encoding='utf-8') as file:
#         table = from_csv(file)
#         print(table)
#     print("Envoi : ")
#     print(logs)