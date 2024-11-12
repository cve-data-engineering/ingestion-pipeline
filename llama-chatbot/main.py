import streamlit as st
from llama_index.core import Settings, VectorStoreIndex, ServiceContext
from llama_index.vector_stores.pinecone import PineconeVectorStore
from llama_index.embeddings.openai import OpenAIEmbedding
from llama_index.llms.openai import OpenAI
from llama_index.core.memory import ChatMemoryBuffer
from llama_index.core.prompts import PromptTemplate
from pinecone import Pinecone
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class CVEChatbot:
    def __init__(self):
        # Initialize Pinecone
        self.pc = Pinecone(api_key=os.getenv("PINECONE_API_KEY"))

        # Initialize LLM
        self.llm = OpenAI(
            model="gpt-3.5-turbo",
            temperature=0.1,
            api_key=os.getenv("OPENAI_API_KEY")
        )

        # Initialize embeddings
        self.embed_model = OpenAIEmbedding(
            api_key=os.getenv("OPENAI_API_KEY")
        )

        # Initialize vector store
        self.vector_store = PineconeVectorStore(
            pinecone_index=self.pc.Index("cve-index"),
            embedding_dimension=1536
        )

        # Configure global settings
        Settings.llm = self.llm
        Settings.embed_model = self.embed_model

        # Initialize vector store index
        self.index = VectorStoreIndex.from_vector_store(
            vector_store=self.vector_store,
        )

        # Initialize chat memory
        self.memory = ChatMemoryBuffer.from_defaults(token_limit=1500)

        # Create chat engine
        self.chat_engine = self.index.as_chat_engine(
            chat_mode="context",
            memory=self.memory,
            system_prompt="""You are a cybersecurity expert assistant. Use the context to answer questions.
            Be specific and provide technical details when available. If you don't know the answer, just say that you don't know.
            Include relevant CVE IDs, severity levels, and technical details in your response."""
        )

    def get_response(self, query: str):
        """Get response using RAG"""
        try:
            response = self.chat_engine.chat(query)
            source_nodes = response.source_nodes

            return {
                "answer": response.response,
                "source_documents": [
                    {
                        "page_content": node.node.text,
                        "metadata": node.node.metadata
                    } for node in source_nodes
                ]
            }
        except Exception as e:
            st.error(f"Error getting response: {str(e)}")
            return None


def format_response(response_data):
    """Format the RAG response and source documents"""
    if not response_data:
        return ""

    formatted_response = f"""
    **Answer**: {response_data['answer']}

    **Source Documents**:
    """

    for doc in response_data.get('source_documents', []):
        metadata = doc['metadata']
        formatted_response += f"""
        ---
        **CVE ID**: {metadata.get('cve_id')}
        **Severity**: {metadata.get('severity')}
        **CVSS Score**: {metadata.get('score')}
        **Published**: {metadata.get('published_date')}
        """

    return formatted_response


def main():
    st.title("CVE Intelligence Chatbot")
    st.write("Ask questions about CVEs and get detailed analysis.")

    # Initialize chatbot
    if 'chatbot' not in st.session_state:
        st.session_state.chatbot = CVEChatbot()

    # Initialize chat history
    if 'chat_history' not in st.session_state:
        st.session_state.chat_history = []

    # Query input
    user_query = st.text_input("Ask about CVEs:", key="user_input")

    # Search button
    if st.button("Send"):
        if user_query:
            with st.spinner("Analyzing your query..."):
                # Get RAG response
                response_data = st.session_state.chatbot.get_response(user_query)

                # Add to chat history
                st.session_state.chat_history.append({
                    "query": user_query,
                    "response": response_data
                })
        else:
            st.warning("Please enter a query.")

    # Display chat history
    st.subheader("Conversation History")
    for item in reversed(st.session_state.chat_history):
        st.write(f"**You**: {item['query']}")
        st.markdown(format_response(item['response']))

    # Add filters in sidebar
    st.sidebar.title("Search Filters")
    severity_filter = st.sidebar.multiselect(
        "Severity Level",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )

    date_range = st.sidebar.date_input(
        "Date Range",
        value=[],
        max_value=None,
        min_value=None,
        key=None,
    )


if __name__ == "__main__":
    main()