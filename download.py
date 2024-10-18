import requests
import zipfile
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class ZipDownloader:
    def __init__(self, url, zip_path='main.zip', extract_dir='extracted_files'):
        self.url = url
        self.zip_path = zip_path
        self.extract_dir = extract_dir
        logging.info(f'Initialized ZipDownloader with URL: {url}')

    def download_zip(self):
        logging.info(f'Starting download from {self.url}')
        response = requests.get(self.url)
        with open(self.zip_path, 'wb') as file:
            file.write(response.content)
        logging.info(f'Download completed and saved to {self.zip_path}')

    def extract_zip(self):
        logging.info(f'Starting extraction of {self.zip_path}')
        with zipfile.ZipFile(self.zip_path, 'r') as zip_ref:
            zip_ref.extractall(self.extract_dir)
        logging.info(f'Extraction completed to directory {self.extract_dir}')

    def process_data(self):
        logging.info(f'Starting to process data in {self.extract_dir}')
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                logging.info(f'Found file: {os.path.join(root, file)}')
        logging.info('Data processing completed')

    def cleanup(self):
        logging.info(f'Removing downloaded zip file {self.zip_path}')
        os.remove(self.zip_path)
        logging.info('Cleanup completed')
