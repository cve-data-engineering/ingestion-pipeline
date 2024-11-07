import os
import json
import logging
import snowflake.connector

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class SnowflakeUploader:
    def __init__(self, directory, snowflake_config):
        """
        Initialize the uploader with the directory containing JSON files and Snowflake connection configuration.

        :param directory: Directory where JSON files are stored.
        :param snowflake_config: Dictionary containing Snowflake connection parameters.
        """
        self.directory = directory
        self.snowflake_config = snowflake_config
        logging.info(f'Initialized SnowflakeUploader with directory: {directory}')

    def connect_to_snowflake(self):
        """
        Establish a connection to the Snowflake database.

        :return: Snowflake connection object.
        """
        logging.info('Connecting to Snowflake...')
        conn = snowflake.connector.connect(
            user=self.snowflake_config['user'],
            password=self.snowflake_config['password'],
            account=self.snowflake_config['account'],
            warehouse=self.snowflake_config['warehouse'],
            database=self.snowflake_config['database'],
            schema=self.snowflake_config['schema']
        )
        logging.info('Connected to Snowflake')
        return conn

    def upload_json_to_snowflake(self):
        """
        Read JSON files from the specified directory and upload them to the Snowflake database.
        """
        conn = self.connect_to_snowflake()

        try:
            cursor = conn.cursor()

            for root, dirs, files in os.walk(self.directory):
                for file in files:
                    if file.endswith('.json'):
                        file_path = os.path.join(root, file)
                        logging.info(f'Reading JSON file: {file_path}')

                        with open(file_path, 'r') as json_file:
                            data = json.load(json_file)

                            # Extracting required fields
                            cve_id = data['cveMetadata']['cveId']
                            date_updated = data['cveMetadata']['dateUpdated']
                            date_published = data['cveMetadata']['datePublished']
                            json_data_str = json.dumps(data)

                            # Insert data into Snowflake table
                            insert_query = f"""
                                                INSERT INTO CVE_PERSISTENT (cveID, dateUpdated, datePublished, Data)
                                                SELECT %s, %s, %s, PARSE_JSON(%s)
                                                        """
                            cursor.execute(insert_query, (
                            cve_id, date_updated, date_published, json_data_str))
                            logging.info(f'Inserted record into Snowflake: {cve_id}')

            conn.commit()
            logging.info('All JSON data uploaded successfully')

        except Exception as e:
            logging.error(f'Error uploading data to Snowflake: {e}')

        finally:
            cursor.close()
            conn.close()
            logging.info('Snowflake connection closed')


# Example usage
# snowflake_config = {
#     'user': 'your_username',
#     'password': 'your_password',
#     'account': 'your_account',
#     'warehouse': 'your_warehouse',
#     'database': 'your_database',
#     'schema': 'your_schema'
# }
#
# uploader = SnowflakeUploader(directory='extracted_files', snowflake_config=snowflake_config)
# uploader.upload_json_to_snowflake()
