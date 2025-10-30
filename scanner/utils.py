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





