import os
from typing import List
from dotenv import load_dotenv

from llama_index.core import VectorStoreIndex, Document
from llama_index.core import Settings
from llama_index.vector_stores.pinecone import PineconeVectorStore
from llama_index.embeddings.openai import OpenAIEmbedding
from llama_index.llms.openai import OpenAI
from pinecone import Pinecone
from llama_index.core import StorageContext
from llama_index.core import Prompt

load_dotenv()
class CVEChatBotLlama:
    def __init__(
        self,
        pinecone_index_name: str = "cve-index-2",
        namespace: str = "",
        top_k: int = 5,
        llm_model: str = "gpt-4",
        temperature: float = 0.0
    ):
        """
        Initializes the CVE chatbot with a Pinecone vector store and LlamaIndex.

        Args:
            pinecone_index_name (str): The name of your Pinecone index.
            namespace (str): Namespace for Pinecone embeddings.
            top_k (int): Number of top results to retrieve.
            llm_model (str): The LLM model name to use (e.g., "gpt-4").
            temperature (float): Temperature for the LLM.
        """
        self.top_k = top_k

        pc = Pinecone(
            api_key=os.environ.get("PINECONE_API_KEY")
        )

        # Connect to the existing Pinecone index
        if pinecone_index_name not in pc.list_indexes().names():
            raise ValueError(f"Pinecone index '{pinecone_index_name}' does not exist.")
        self.pinecone_index = pc.Index(name=pinecone_index_name)
        
        Settings.embed_model = OpenAIEmbedding(
            openai_api_key=os.environ.get("OPENAI_API_KEY"),
            model="text-embedding-ada-002"
        )

        Settings.llm = OpenAI(model="gpt-4", temperature=0.1)
        self.llm = Settings.llm
        Settings.num_output = 1024

        self.vector_store = PineconeVectorStore(pinecone_index=self.pinecone_index)
        storage_context = StorageContext.from_defaults(vector_store=self.vector_store)
        self.index = VectorStoreIndex([], storage_context=storage_context)        # Create a VectorStoreIndex with no local docs

    def _get_relevant_docs(self, query: str) -> List[Document]:
        """
        Retrieve top_k most relevant documents from Pinecone based on the query.
        """
        query_engine = self.index.as_query_engine(similarity_top_k=self.top_k)
        response = query_engine.query(query)
        # print("response", response)
        # Extract the source nodes (documents) from the response
        docs = response.source_nodes
        return docs
    
    def _generate_answer(self, query: str, docs: List[Document]) -> str:
        context_str = "\n".join([
            f"- CVE ID: {doc.metadata.get('cve_id', 'Unknown')} | {doc.text.strip()}"
            for doc in docs
        ])

        prompt_str = f"""
    You are a cybersecurity assistant. You have been given the following CVE documents as context:
    Use the following pieces of context to provide a detailed analysis of the CVE in question. Your response should include:
    1. A clear description of the vulnerability
    2. The severity and impact assessment
    3. Specific technical details about the vulnerability
    4. Step-by-step mitigation strategies
    5. Additional security recommendations

    {context_str}

    User Query: {query}

    Task: Answer the user's query using the provided CVE information.
    Cite the CVEs by their ID if relevant.
    If you do not find relevant CVEs, say you have no data.
    Be concise and factual.
    You are a cybersecurity expert assistant specializing in CVE analysis and mitigation strategies.
    """

        # Create a Prompt object from the string
        prompt = Prompt(template=prompt_str)
        answer = self.llm.predict(prompt)
        return answer


    def get_response(self, user_query: str) -> str:
        """
        Main method to get response for a user query:
        - Retrieve documents from Pinecone
        - Generate answer from LLM
        """
        docs = self._get_relevant_docs(user_query)
        answer = self._generate_answer(user_query, docs)
        return answer
