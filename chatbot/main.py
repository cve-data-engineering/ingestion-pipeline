import streamlit as st
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_pinecone import PineconeVectorStore
from pinecone import Pinecone
from langchain.chains import ConversationalRetrievalChain
from langchain.memory import ConversationBufferMemory
from langchain_core.prompts import PromptTemplate
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class CVEChatbot:
    def __init__(self):
        self.pc = Pinecone(api_key=os.getenv("PINECONE_API_KEY"))

        # Explicitly specify the embedding model
        self.embeddings = OpenAIEmbeddings(
            model="text-embedding-ada-002",
            api_key=os.getenv("OPENAI_API_KEY")
        )

        self.llm = ChatOpenAI(
            model_name="gpt-3.5-turbo",
            temperature=0.1,
            api_key=os.getenv("OPENAI_API_KEY")
        )

        self.vector_store = PineconeVectorStore(
            index_name="cve-index",
            embedding=self.embeddings
        )

        self.memory = ConversationBufferMemory(
            memory_key="chat_history",
            return_messages=True,
            output_key="answer",
            input_key="question"
        )

        self.qa_prompt = PromptTemplate(
            template="""You are a cybersecurity expert assistant specializing in CVE analysis and mitigation strategies. 

                    Use the following pieces of context to provide a detailed analysis of the CVE in question. Your response should include:
                    1. A clear description of the vulnerability
                    2. The severity and impact assessment
                    3. Specific technical details about the vulnerability
                    4. Step-by-step mitigation strategies
                    5. Additional security recommendations

                    If the CVE exists but specific details are limited, provide general security recommendations based on the vulnerability type.

                    Context: {context}

                    Question: {question}

                    Provide a comprehensive response including all available technical details and practical mitigation steps:""",
            input_variables=["context", "question"]
        )

        self.qa_chain = ConversationalRetrievalChain.from_llm(
            llm=self.llm,
            retriever=self.vector_store.as_retriever(
                search_type="similarity_score_threshold",
                search_kwargs={
                    "k": 8,
                    "score_threshold": 0.7
                }
            ),
            memory=self.memory,
            combine_docs_chain_kwargs={
                "prompt": self.qa_prompt,
                "document_separator": "\n\n"
            },
            chain_type="stuff",
            return_source_documents=True,
            verbose=True
        )

    def get_response(self, query: str):
        try:
            # Enhance query with CVE context
            enhanced_query = self._enhance_query(query)

            # Get RAG response
            response = self.qa_chain({"question": enhanced_query})

            # If response indicates no information, try fallback strategy
            if "no information available" in response["answer"].lower():
                fallback_response = self._get_fallback_response(query)
                if fallback_response:
                    response["answer"] = fallback_response

            return {
                "answer": response["answer"],
                "source_documents": response["source_documents"],
                "similar_docs": self._get_similar_docs(query)
            }
        except Exception as e:
            st.error(f"Error getting response: {str(e)}")
            return None

    def _enhance_query(self, query: str):
        """Enhance the query with additional context"""
        if "CVE-" in query:
            return f"{query} Include technical details, severity, and specific mitigation steps if available."
        return query

    def _get_similar_docs(self, query: str, k=5):
        """Get similar documents with improved scoring"""
        return self.vector_store.similarity_search_with_score(
            query=query,
            k=k,
            filter={"score": {"$gt": 0.5}}
        )

    def _get_fallback_response(self, query: str):
        """Provide fallback response for cases with limited information"""
        cve_pattern = r'CVE-\d{4}-\d+'
        import re

        cve_match = re.search(cve_pattern, query)
        if not cve_match:
            return None

        cve_id = cve_match.group(0)

        # Try to get basic information about the CVE type
        basic_info = self.vector_store.similarity_search(
            f"What type of vulnerability is {cve_id}?",
            k=3
        )

        if basic_info:
            return f"While detailed information about {cve_id} is limited, based on similar vulnerabilities, here are recommended security practices and mitigation strategies..."

        return None


def format_response(response_data):
    """Format the RAG response and source documents"""
    if not response_data:
        return ""

    formatted_response = f"""
    **Answer**: {response_data['answer']}

    **Top Matches (with similarity scores)**:
    """

    # Add similarity search results
    for doc, score in response_data.get('similar_docs', []):
        formatted_response += f"""
        ---
        **Similarity Score**: {score:.4f}
        **CVE ID**: {doc.metadata.get('cve_id')}
        **Text**: {doc.page_content[:200]}...
        """

    formatted_response += "\n\n**Source Documents Used in Response**:"

    for doc in response_data.get('source_documents', []):
        metadata = doc.metadata
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
