from virus_total_apis import PublicApi
import csv
import sys
import argparse

API_KEY = "Api_key"
api = PublicApi(API_KEY)

# Parsea los argumentos de línea de comandos
def parse_arguments():
    parser = argparse.ArgumentParser(description="Recibe un archivo de entrada tipo txt o csv, escanea los dominios y genera un archivo CSV de salida.")
    parser.add_argument("-f", "--input_file", help="Archivo de entrada (txt o csv) que contiene los dominios.")
    parser.add_argument("-o", "--output_file", help="Archivo de salida CSV para guardar los resultados. Siempre se agrega la extensión .csv, por lo que no es necesario agregar una extensión. Si no se ingresa un archivo se genera uno llamado 'Dominios.csv'")
    parser.add_argument("-c", "--domain_column", type=int, default=1, help="Número de columna del dominio (por defecto: 1).")
    parser.add_argument("--header", action="store_true", help="Indica si el archivo de entrada CSV tiene encabezado.Por defecto, se considera que el archivo no contiene encabezado.")
    return parser.parse_args()

def send_domain_to_virustotal(file_input, output_file):
    # Crear archivo CSV
    with open(output_file, "w", newline="") as csv_file:
        fieldnames = ["Dominio","Virus Total", "Resultado", "Fortinet", "Clasificacion"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        
        for dominio in file_input:
            response = api.get_url_report(dominio)
            
            if response["response_code"] == 200:
                dom = response["results"]["resource"]

                if response["results"]["response_code"] == 1:
                    positivos = response["results"]["positives"]
                    link = response["results"]["permalink"]
                    total = response["results"]["total"]
                    fortinet_result = response["results"]["scans"]["Fortinet"]["detected"]
                    fortinet_clasificacion = response["results"]["scans"]["Fortinet"]["result"]
                    writer.writerow({
                        "Dominio": dom,
                        "Virus Total": link,
                        "Resultado": str(positivos) + '/' + str(total),
                        "Fortinet": fortinet_result,
                        "Clasificacion": fortinet_clasificacion
                    })
                else:
                    #Desconocido
                    writer.writerow({
                        "Dominio": dom,
                        "Virus Total": "Unknown",
                        "Resultado": "Unknown",
                        "Fortinet": "false",
                        "Clasificacion": "Unknown"
                })
            else:
                error = response["response_code"]
                print(f"Error {error} al enviar la solicitud a VirusTotal para el dominio: {dominio}")
                
# Lee los dominios de un archivo .txt o .csv
def read_domain_from_file(file_path, column, has_header):
    dominios = []
    try:
        with open(file_path, "r") as file:
            if file_path.endswith(".csv"):
                reader = csv.reader(file)
                for i, row in enumerate(reader, start=1):
                    if has_header and i == 1:
                        continue  # Omitir la fila del encabezado si está presente
                    try:
                        domain = row[column - 1]
                        dominios.append(domain)
                    except IndexError:
                        print(f"Error al leer el archivo de entrada: la columna {column} no existe en la fila {i}.")
                        sys.exit(1)
            else:
                dominios = file.read().splitlines()
        return dominios
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
    output_file = args.output_file or "Dominios"
    
    # Verifica si el archivo de salida tiene la extensión .csv
    if not output_file.endswith(".csv"):
        output_file += ".csv"

    column = args.domain_column
    header = args.header

    dominios = read_domain_from_file(file_path, column, header)
    send_domain_to_virustotal(dominios, output_file)
