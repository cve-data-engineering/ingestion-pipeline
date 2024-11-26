import logging
import os

from dotenv import load_dotenv
from consumer import MessageConsumer
from processor import SnowflakeUploader


load_dotenv()

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Configuration
    config = {
        'topics': ['cve'],
        'bootstrap_servers': ['localhost:65158'],
        'group_id': 'cve-consumer-group',
        'pinecone_api_key': os.getenv("PINECONE_API_KEY"),
        'openai_api_key': os.getenv("OPENAI_API_KEY"),
        'index_name': 'cve-index'
    }

    password = os.getenv("password")
    snowflake_config = {
        'user': 'FERRET',
        'password': password,
        'account': 'urb63596',
        'warehouse': 'TEST_CVE_WAREHOUSE',
        'database': 'test_cve',
        'schema': 'PUBLIC'
    }

    consumer = None
    try:
        # Initialize and run the consumer
        consumer = MessageConsumer(snowflake_config, **config)
        logging.info("Starting to consume the messages")
        consumer.consume_and_embed_messages()
    except KeyboardInterrupt:
        print("Stopping the consumer...")
    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        # Ensure proper cleanup
        if consumer:
            try:
                consumer.close()
                logging.info("Consumer closed successfully")
            except Exception as e:
                logging.error(f"Error closing consumer: {str(e)}")
