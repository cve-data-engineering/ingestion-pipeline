from kafka import KafkaConsumer
import json
from typing import List, Optional, Callable, Dict
import logging
from langchain_openai import OpenAIEmbeddings
from langchain_pinecone import PineconeVectorStore
from pinecone import Pinecone, ServerlessSpec
import os
from dotenv import load_dotenv
from snowflake import SnowflakeUploader


class MessageConsumer:
    def __init__(
            self,
            snowflake_config,
            topics: List[str],
            bootstrap_servers: List[str],
            group_id: str,
            openai_api_key: str,
            index_name: str = "cve-index",
            auto_offset_reset: str = 'earliest',
            enable_auto_commit: bool = True,
    ):
        self.logger = logging.getLogger(__name__)
        self.topics = topics
        self.index_name = index_name
        self.snowflake_uploader = SnowflakeUploader(snowflake_config)

        # Initialize Pinecone
        self.pc = Pinecone(api_key=os.getenv("PINECONE_API_KEY"))

        # Initialize OpenAI embeddings
        self.embeddings = OpenAIEmbeddings(api_key=openai_api_key)

        # Initialize Pinecone vector store
        self._initialize_pinecone_index()

        try:
            # Initialize Kafka consumer
            self.consumer = KafkaConsumer(
                *topics,
                bootstrap_servers=bootstrap_servers,
                group_id=group_id,
                auto_offset_reset=auto_offset_reset,
                enable_auto_commit=enable_auto_commit,
                value_deserializer=lambda x: json.loads(x.decode('utf-8')),
                api_version=(0, 10, 1),
                security_protocol='PLAINTEXT',
            )
            self.logger.info(f"Consumer initialized for topics: {topics}")
        except Exception as e:
            self.logger.error(f"Failed to initialize consumer: {str(e)}")
            raise

    def _initialize_pinecone_index(self):
        """Initialize Pinecone index if it doesn't exist"""
        try:
            if self.index_name not in self.pc.list_indexes().names():
                self.pc.create_index(
                    name=self.index_name,
                    dimension=1536,  # OpenAI embedding dimension
                    metric="cosine",
                    spec=ServerlessSpec(
                        cloud='aws',
                        region='us-east-1'  # Changed to us-east-1
                    )
                )
            self.vector_store = PineconeVectorStore(
                index_name=self.index_name,
                embedding=self.embeddings
            )
        except Exception as e:
            self.logger.error(f"Failed to initialize Pinecone index: {str(e)}")
            raise

    def _process_cve_for_embedding(self, cve_data: Dict) -> Dict:
        """Process CVE data into a format suitable for embedding"""
        try:
            # Extract relevant information from CVE data
            cve_id = cve_data.get("cveMetadata", {}).get("cveId", "")
            description = cve_data.get("containers", {}).get("cna", {}).get("descriptions", [{}])[0].get("value", "")
            title = cve_data.get("containers", {}).get("cna", {}).get("title", "")

            # Create structured text for embedding
            text_for_embedding = f"""
            Title: {title}
            CVE ID: {cve_id}
            Description: {description}
            """

            # Create metadata
            metadata = {
                "cve_id": cve_id,
                "published_date": cve_data.get("cveMetadata", {}).get("datePublished", ""),
                "updated_date": cve_data.get("cveMetadata", {}).get("dateUpdated", ""),
                "severity": cve_data.get("containers", {}).get("cna", {}).get("metrics", [{}])[0].get("cvssV3_1",
                                                                                                      {}).get(
                    "baseSeverity", ""),
                "score": cve_data.get("containers", {}).get("cna", {}).get("metrics", [{}])[0].get("cvssV3_1", {}).get(
                    "baseScore", 0),
                "cwe_id": cve_data.get("containers", {}).get("cna", {}).get("problemTypes", [{}])[0].get("descriptions",
                                                                                                         [{}])[0].get(
                    "cweId", "")
            }

            return {"text": text_for_embedding, "metadata": metadata}
        except Exception as e:
            self.logger.error(f"Error processing CVE data: {str(e)}")
            raise

    def process_and_store_embedding(self, message):
        """Process a single message and store its embedding"""
        try:
            processed_data = self._process_cve_for_embedding(message.value)

            # Store in Pinecone
            self.vector_store.add_texts(
                texts=[processed_data["text"]],
                metadatas=[processed_data["metadata"]]
            )

            self.logger.info(f"Stored embedding for CVE: {processed_data['metadata']['cve_id']}")
        except Exception as e:
            self.logger.error(f"Error processing message: {str(e)}")
            raise

    def consume_and_embed_messages(self):
        """Consume messages and create embeddings"""
        try:
            while True:
                message_batch = self.consumer.poll(timeout_ms=1000)

                if not message_batch:
                    continue

                for topic_partition, messages in message_batch.items():
                    for message in messages:
                        self.snowflake_uploader.upload_json_to_snowflake(message.value)
                        self.process_and_store_embedding(message)

        except Exception as e:
            self.logger.error(f"Error consuming messages: {str(e)}")
            raise
        finally:
            self.close()

    def close(self):
        """Close the consumer connection"""
        if hasattr(self, 'consumer'):
            self.consumer.close()
            self.logger.info("Consumer closed")
            
    