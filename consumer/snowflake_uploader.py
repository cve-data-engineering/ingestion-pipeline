import json
import logging
import snowflake.connector

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class SnowflakeUploader:
    def __init__(self, snowflake_config):
        """
        Initialize the uploader with the directory containing JSON files and Snowflake connection configuration.

        :param directory: Directory where JSON files are stored.
        :param snowflake_config: Dictionary containing Snowflake connection parameters.
        """
        self.snowflake_config = snowflake_config
        self.snowflake_connection = self.connect_to_snowflake()

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

    def upload_json_to_snowflake(self, data):
        """
        Upload JSON data from Kafka messages directly to the Snowflake database.
        """
        conn = self.snowflake_connection

        try:
            cursor = conn.cursor()

            # Extracting required fields from the JSON message
            cve_id = data['cveMetadata']['cveId']
            date_updated = data['cveMetadata']['dateUpdated']
            date_published = data['cveMetadata']['datePublished']
            json_data_str = json.dumps(data)

            # Insert data into Snowflake table
            insert_query = """
                INSERT INTO CVE_PERSISTENT (cveID, dateUpdated, datePublished, Data)
                SELECT %s, %s, %s, PARSE_JSON(%s)
            """
            cursor.execute(insert_query, (cve_id, date_updated, date_published, json_data_str))
            logging.info(f'Inserted record into Snowflake: {cve_id}')

            conn.commit()
            logging.info('JSON data uploaded successfully')

        except Exception as e:
            logging.error(f'Error uploading data to Snowflake: {e}')

        finally:
            # cursor.close()
            # conn.close()
            logging.info('Snowflake connection closed')
