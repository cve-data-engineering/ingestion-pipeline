import os
import psycopg
from dotenv import load_dotenv


# Singleton class to connect to PostgreSQL DB
class PostgresConnector:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(PostgresConnector, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'initialized'):  # Ensure __init__ is run only once
            load_dotenv()
            self.host = os.environ['DB_HOST']
            self.port = os.getenv('DB_PORT', 5432)
            self.database = os.environ['DB_NAME']
            self.user = os.environ['DB_USER']
            self.password = os.environ['DB_PASSWORD']
            self.connection = None
            self.initialized = True

    def connect(self):
        try:
            self.connection = psycopg.connect(
                host=self.host,
                port=self.port,
                dbname=self.database,
                user=self.user,
                password=self.password
            )
            print("Connection to PostgreSQL DB successful")
        except Exception as e:
            print(f"Error: {e}")
            self.connection = None

    def close(self):
        if self.connection:
            self.connection.close()
            print("PostgreSQL connection closed")
