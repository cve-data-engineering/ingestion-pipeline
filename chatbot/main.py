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
            template="""You are a cybersecurity expert assistant. Use the following pieces of context to answer the question at the end. 
            If you don't know the answer, just say that you don't know. Try to be specific and provide technical details when available.

            Context: {context}

            Question: {question}

            Answer the question based on the context provided. Include relevant CVE IDs, severity levels, and technical details in your response:""",
            input_variables=["context", "question"]
        )

        self.qa_chain = ConversationalRetrievalChain.from_llm(
            llm=self.llm,
            retriever=self.vector_store.as_retriever(
                search_type="similarity",
                search_kwargs={"k": 5}
            ),
            memory=self.memory,
            combine_docs_chain_kwargs={"prompt": self.qa_prompt},
            return_source_documents=True,
            chain_type="stuff"
        )

    def get_response(self, query: str):
        """Get response using RAG"""
        try:
            # First, get the query embedding to verify the model
            query_embedding = self.embeddings.embed_query(query)
            print(f"\nQuery Embedding Length: {len(query_embedding)}")  # Should be 1536 for ada-002

            # Get similar documents directly from vector store first
            similar_docs = self.vector_store.similarity_search_with_score(
                query=query,
                k=5
            )

            # Print top 5 matches with similarity scores
            print("\nTop 5 Similar Documents:")
            for doc, score in similar_docs:
                print(f"\nScore: {score}")
                print(f"CVE ID: {doc.metadata.get('cve_id')}")
                print(f"Text: {doc.page_content[:200]}...")  # Print first 200 chars

            # Get RAG response
            response = self.qa_chain({"question": query})

            return {
                "answer": response["answer"],
                "source_documents": response["source_documents"],
                "similar_docs": similar_docs  # Include similarity search results
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
