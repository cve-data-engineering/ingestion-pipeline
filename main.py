from download import ZipDownloader
from processor import SnowflakeUploader
import os
from dotenv import load_dotenv
def main():
    load_dotenv()
    url = 'https://github.com/CVEProject/cvelistV5/releases/download/cve_2024-10-17_2300Z/2024-10-17_delta_CVEs_at_2300Z.zip'
    downloader = ZipDownloader(url)
    downloader.download_zip()
    downloader.extract_zip()
    # downloader.process_data()

    password = os.getenv("password")
    snowflake_config = {
        'user': 'FALCON',
        'password': password,
        'account': 'urb63596',
        'warehouse': 'TEST_CVE_WAREHOUSE',
        'database': 'test_cve',
        'schema': 'PUBLIC'
    }

    uploader = SnowflakeUploader(directory='extracted_files', snowflake_config=snowflake_config)
    uploader.upload_json_to_snowflake()
    downloader.cleanup()



if __name__ == '__main__':
    main()
