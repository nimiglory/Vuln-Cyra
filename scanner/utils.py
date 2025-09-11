import requests
from bs4 import BeautifulSoup
import shutil
import os

def basic_scrape_info(url):
    """Fetches and returns the title of a webpage."""
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        title = soup.title.string if soup.title else "No Title Found"
        return f"Website Title: {title}"
    except Exception as e:
        return f"Scraping failed: {str(e)}"




# # ✅ Path to your project base directory
# BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# NMAP_PATH = r"C:\Users\Glory.Asifamabia\Desktop\Vuln Cyra\venv\Lib\site-packages\nmap"
# SQLMAP_PATH = r"C:\Users\Glory.Asifamabia\Desktop\Vuln Cyra\venv\Scripts"

# # ✅ Path to your virtual environment scripts (if you need to call python/sqlmap inside venv)
# VENV_SCRIPTS_PATH = r"C:\Users\Glory.Asifamabia\Desktop\Vuln Cyra\venv\Scripts\python.exe"
