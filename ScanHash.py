from virus_total_apis import PublicApi
from hashlib import md5
import csv
import json
import requests
import sys
import argparse

API_KEY = "Api_Key"
api = PublicApi(API_KEY)

# Parsea los argumentos de línea de comandos
def parse_arguments():
    parser = argparse.ArgumentParser(description="Recibe un archivo de entrada tipo txt o csv y escanea hashes y genera un archivo CSV de salida.")
    parser.add_argument("-f", "--input_file", help="Archivo de entrada (txt o csv) que contiene los hashes.")
    parser.add_argument("-o", "--output_file", help="Archivo de salida CSV para guardar los resultados. Si no es csv o no tiene extensión, se agrega la extensión .csv")
    parser.add_argument("-c", "--hash_column", type=int, default=1, help="Número de columna del hash (por defecto: 1).")
    parser.add_argument("--header", action="store_true", help="Indica si el archivo CSV tiene encabezado.")
    return parser.parse_args()


def send_hash_to_virustotal(file_hashes, output_file):
    
    headers = {
        "x-apikey": API_KEY
    }
    # Crear archivo CSV
    with open(output_file, "w", newline="") as csv_file:
        fieldnames = ["SHA256", "MD5", "Link", "Result Total", "Fortinet Result", "McAfee Result"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        
        for file_hash in file_hashes:
            #url = url.format(file_hash)
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                json_response = response.json()
                attributes = json_response["data"]["attributes"]

                total_fields = [
                    'harmless',
                    'type-unsupported',
                    'suspicious',
                    'confirmed-timeout',
                    'timeout',
                    'failure',
                    'malicious',
                    'undetected'
                ]
                total = sum(int(attributes['last_analysis_stats'].get(field, 0)) for field in total_fields)

                hash_value = attributes["sha256"]
                md5 = attributes["md5"]
                link = json_response["data"]["links"]["self"]
                result_total = f"{attributes['last_analysis_stats']['malicious']}/{total}"
                fortinet_result = attributes["last_analysis_results"]["Fortinet"]["result"]
                mcafee_result = attributes["last_analysis_results"]["McAfee"]["result"]
                
                writer.writerow({
                    "SHA256": hash_value,
                    "MD5": md5,
                    "Link": link,
                    "Result Total": result_total,
                    "Fortinet Result": fortinet_result,
                    "McAfee Result": mcafee_result
                })
            else:
                print(f"Error al enviar la solicitud a VirusTotal para el hash: {file_hash}")

# Lee los hashes de un archivo .txt o .csv
def read_hashes_from_file(file_path, hash_column, has_header):
    hashes = []
    try:
        with open(file_path, "r") as file:
            if file_path.endswith(".csv"):
                reader = csv.reader(file)
                for i, row in enumerate(reader, start=1):
                    if has_header and i == 1:
                        continue  # Omitir la fila del encabezado si está presente
                    try:
                        hash_value = row[hash_column - 1]
                        hashes.append(hash_value)
                    except IndexError:
                        print(f"Error al leer el archivo de entrada: la columna {hash_column} no existe en la fila {i}.")
                        sys.exit(1)
            else:
                hashes = file.read().splitlines()
        return hashes
    except FileNotFoundError:
        print(f"El archivo de entrada '{file_path}' no existe.")
        sys.exit(1)

if __name__ == "__main__":
   # Parsea los argumentos de línea de comandos
    args = parse_arguments()

    # Verifica si se proporcionó un archivo de entrada
    if args.input_file is None:
        print("Por favor, especifique un archivo de entrada.")
        sys.exit(1)
    
    # Verifica si el archivo de entrada tiene la extensión .txt o .csv
    if not args.input_file.endswith((".txt", ".csv")):
        print("El archivo de entrada debe tener la extensión .txt o .csv.")
        sys.exit(1)

    # Obtiene el archivo de entrada del argumento
    file_path = args.input_file
    
    # Obtiene el archivo de salida del argumento si se proporciona, de lo contrario usa un valor predeterminado
    output_file = args.output_file or "output.csv"
    
    # Verifica si el archivo de salida tiene la extensión .csv
    if not output_file.endswith(".csv"):
        output_file += ".csv"

    column = args.hash_column
    header = args.header

    hashes = read_hashes_from_file(file_path, column, header)
    send_hash_to_virustotal(hashes, output_file)