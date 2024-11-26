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
        'bootstrap_servers': ['10.0.0.223:9092'],
        'group_id': 'cve-consumer-group',
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
    
    user = os.getenv("user")
    password = os.getenv("password")
    account = os.getenv("account")
    warehouse = os.getenv("warehouse")
    database = os.getenv("database")
    schema = os.getenv("schema")

    snowflake_config = {
        'user': user,
        'password': password,
        'account': account,
        'warehouse': warehouse,
        'database': database,
        'schema': schema
    }
    
    try:
        # Initialize and run the consumer
        consumer = MessageConsumer(snowflake_config, **config)
        logging.info("Starting to consume the messages")
        # consumer.consume_and_embed_messages()
        
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
