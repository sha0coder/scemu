import requests
import time
import sys

API_KEY = "141adc1db02b7d093787791cb3e18aea2b864dac99010bbad689e61db82a92b3"  # Reemplázalo con tu clave de la API de VirusTotal
INPUT_FILE = sys.argv[1]  # Archivo con los hashes
OUTPUT_FILE = "results.txt"  # Salida con los resultados
VT_URL = "https://www.virustotal.com/api/v3/files/{}"

def get_virus_total_report(hash_md5):
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(VT_URL.format(hash_md5), headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        return data['data']['attributes']['last_analysis_stats']['malicious']
    elif response.status_code == 404:
        return "Not Found"
    else:
        return f"Error {response.status_code}"

def main():
    with open(INPUT_FILE, "r") as infile, open(OUTPUT_FILE, "w") as outfile:
        for line in infile:
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) >= 1:
                hash_md5 = parts[0]
                filename = parts[1] if len(parts) > 1 else "N/A"

                print(f"Checking hash: {hash_md5} ({filename})")
                detections = get_virus_total_report(hash_md5)
                outfile.write(f"{hash_md5} {filename} {detections}\n")
                print(f"{hash_md5} -> {detections} detections")
                
                time.sleep(16)  # Evita exceder el límite de la API gratuita (4 por minuto)
    print("Results saved to:", OUTPUT_FILE)

if __name__ == "__main__":
    main()
