# from airflow import DAG
# from airflow.operators.bash import BashOperator
# from airflow.operators.python import PythonOperator
# from airflow.operators.empty import EmptyOperator
# from airflow.operators.python import BranchPythonOperator
# from datetime import datetime, timedelta
# from airflow.utils.trigger_rule import TriggerRule
# import os
# from dotenv import load_dotenv
# from src.consumer import MessageConsumer

# default_args = {
#         'owner': 'airflow',
#         'depends_on_past': False,
#         'retries': 1,
#         'retry_delay': timedelta(minutes=5),
# }

# load_dotenv()
# airflow_sf_config = {
#     'topics': ['cve'],
#     'bootstrap_servers': ['10.0.0.223:9092'],
#     'group_id': 'cve-consumer-group',
#     'openai_api_key': os.getenv("OPENAI_API_KEY"),
#     'index_name': 'cve-index'
# }

# airflow_pc_config = {
#     'topics': ['cve'],
#     'bootstrap_servers': ['10.0.0.223:9092'],
#     'group_id': 'cve-consumer-group-pinecone',
#     'openai_api_key': os.getenv("OPENAI_API_KEY"),
#     'index_name': 'cve-index'
# }

# consumer = None

# user = os.getenv("user")
# password = os.getenv("password")
# account = os.getenv("account")
# warehouse = os.getenv("warehouse")
# database = os.getenv("database")
# schema = os.getenv("schema")

# snowflake_config = {
#     'user': user,
#     'password': password,
#     'account': account,
#     'warehouse': warehouse,
#     'database': database,
#     'schema': schema
# }
 
# def insert_data_in_snowflake():
#     print("Running snowflake upload throgh DAG")
#     consumer_object = MessageConsumer(snowflake_config, **airflow_sf_config)
#     consumer_object.consume_and_embed_messages(False)

# def create_and_store_embeddings():
#     print("Creating and storing embeddings")
#     MessageConsumer(snowflake_config, **airflow_pc_config).consume_and_embed_messages(True)

# with DAG(
#     'data_extraction',
#     default_args=default_args,
#     description='A consolidated dag for ETL',
#     schedule=None,
#     start_date=datetime(2024, 11, 13),
#     catchup=False,
# ) as dag:
    
   

#     run_go_app = BashOperator(
#         task_id='run_producer',
#         bash_command='/opt/airflow/bin/producer',
#         env={
#             'KAFKA_BOOTSTRAP_SERVERS': '10.0.0.223:9092',
#             'DELTA_CVE_URL': 'https://github.com/CVEProject/cvelistV5/releases/download/cve_2024-11-09_0500Z/2024-11-09_delta_CVEs_at_0500Z.zip',
#             'DELTA_CVE_DIR': 'internal/data/deltaCves',
#             'KAFKA_TOPIC': 'cve'
#         },
#         dag=dag,
#     )
    
#     upload_to_snowflake_task= PythonOperator(
#         task_id='upload_to_snowflake',
#         python_callable=insert_data_in_snowflake,
#         op_kwargs={'inactivity_timeout': 10}
#     )

#     create_and_store_embeddings_task= PythonOperator(
#         task_id='create_and_store_embeddings_task',
#         python_callable=create_and_store_embeddings,
#         op_kwargs={'inactivity_timeout': 10}
#     )
    
#     run_go_app >> upload_to_snowflake_task >> create_and_store_embeddings_task

# # if __name__ == "__main__":
# #     insert_data_in_snowflake()



from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.operators.python import PythonOperator
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from src.consumer import MessageConsumer


class DataExtractionDAG:
    def __init__(self):
        # Load environment variables
        load_dotenv()
        self.default_args = {
            'owner': 'airflow',
            'depends_on_past': False,
            'retries': 1,
            'retry_delay': timedelta(minutes=5),
        }
        self.snowflake_config = self._get_snowflake_config()
        self.airflow_sf_config = {
            'topics': ['cve'],
            'bootstrap_servers': ['10.0.0.223:9092'],
            'group_id': 'cve-consumer-group',
            'openai_api_key': os.getenv("OPENAI_API_KEY"),
            'index_name': 'cve-index'
        }
        self.airflow_pc_config = {
            'topics': ['cve'],
            'bootstrap_servers': ['10.0.0.223:9092'],
            'group_id': 'cve-consumer-group-pinecone',
            'openai_api_key': os.getenv("OPENAI_API_KEY"),
            'index_name': 'cve-index'
        }

    def _get_snowflake_config(self):
        """Load Snowflake connection details from environment variables."""
        return {
            'user': os.getenv("user"),
            'password': os.getenv("password"),
            'account': os.getenv("account"),
            'warehouse': os.getenv("warehouse"),
            'database': os.getenv("database"),
            'schema': os.getenv("schema")
        }

    def insert_data_in_snowflake(self):
        """Python callable for uploading data to Snowflake."""
        print("Running snowflake upload through DAG")
        consumer_object = MessageConsumer(self.snowflake_config, **self.airflow_sf_config)
        consumer_object.consume_and_embed_messages(False)

    def create_and_store_embeddings(self):
        """Python callable for creating and storing embeddings."""
        print("Creating and storing embeddings")
        MessageConsumer(self.snowflake_config, **self.airflow_pc_config).consume_and_embed_messages(True)

    def build_dag(self):
        """Define and construct the DAG."""
        with DAG(
            'data_extraction',
            default_args=self.default_args,
            description='A consolidated DAG for ETL',
            schedule=None,
            start_date=datetime(2024, 11, 13),
            catchup=False,
        ) as dag:
            # Tasks
            run_go_app = BashOperator(
                task_id='run_producer',
                bash_command='/opt/airflow/bin/producer',
                env={
                    'KAFKA_BOOTSTRAP_SERVERS': '10.0.0.223:9092',
                    'DELTA_CVE_URL': 'https://github.com/CVEProject/cvelistV5/releases/download/cve_2024-11-09_0500Z/2024-11-09_delta_CVEs_at_0500Z.zip',
                    'DELTA_CVE_DIR': 'internal/data/deltaCves',
                    'KAFKA_TOPIC': 'cve'
                },
            )

            upload_to_snowflake_task = PythonOperator(
                task_id='upload_to_snowflake',
                python_callable=self.insert_data_in_snowflake,
                op_kwargs={'inactivity_timeout': 10}
            )

            create_and_store_embeddings_task = PythonOperator(
                task_id='create_and_store_embeddings_task',
                python_callable=self.create_and_store_embeddings,
                op_kwargs={'inactivity_timeout': 10}
            )

            # Task dependencies
            run_go_app >> upload_to_snowflake_task >> create_and_store_embeddings_task

        return dag


# Instantiate the DAG
data_extraction_dag = DataExtractionDAG()
dag = data_extraction_dag.build_dag()
