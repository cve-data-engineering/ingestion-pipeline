import asyncio
import streamlit as st
from llama_index.core import Settings, VectorStoreIndex
from llama_index.core.tools import QueryEngineTool, ToolMetadata
from llama_index.core.agent import ReActAgent
from llama_index.llms.openai import OpenAI
from llama_index.embeddings.openai import OpenAIEmbedding
from llama_index.vector_stores.pinecone import PineconeVectorStore
from llama_index.core.query_engine import RetryQueryEngine
from llama_index.core.schema import TextNode
from llama_index.core.evaluation import RelevancyEvaluator
from llama_index.core.callbacks import CallbackManager
from llama_index.core.objects import ObjectIndex
from pinecone import Pinecone
import requests
from bs4 import BeautifulSoup
import os
from dotenv import load_dotenv

from chatbot.main import CVEChatbot

load_dotenv()


class CVEVerificationAgent:
    def __init__(self):
        load_dotenv()

        # Initialize components
        self.pc = Pinecone(api_key=os.getenv("PINECONE_API_KEY"))

        Settings.llm = OpenAI(
            model="gpt-3.5-turbo",
            temperature=0.1,
            api_key=os.getenv("OPENAI_API_KEY")
        )
        Settings.embed_model = OpenAIEmbedding(
            api_key=os.getenv("OPENAI_API_KEY"),
            model="text-embedding-ada-002",
        )

        # Initialize vector store
        self.vector_store = PineconeVectorStore(
            pinecone_index=self.pc.Index("cve-index"),
            embedding_dimension=1536
        )

        self.index = VectorStoreIndex.from_vector_store(
            vector_store=self.vector_store
        )

        self.query_engine = self.index.as_query_engine(
            similarity_top_k=3
        )

        # Add tools for the agent
        tools = [
            QueryEngineTool(
                query_engine=self.query_engine,
                metadata=ToolMetadata(
                    name="cve_search",
                    description="Searches for CVE information and vulnerabilities related to specific technologies"
                )
            )
        ]

        # Initialize ReAct agent
        self.agent = ReActAgent.from_tools(
            tools,
            llm=Settings.llm,
            verbose=True
        )

        self.technology_query_engine = self.index.as_query_engine(
            similarity_top_k=1,
            structured_answer_filtering=True
        )

    def fetch_nvd_data(self, cve_id: str):
        """Fetch CVE data from NVD API"""
        try:
            api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(api_url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data and data['vulnerabilities']:
                    return data['vulnerabilities'][0]
            return None
        except Exception as e:
            st.error(f"Error fetching NVD data: {e}")
            return None

    def get_mitigation_strategies(self, cve_data):
        """Generate mitigation strategies based on vulnerability type"""
        try:
            # Extract vulnerability type from CWE
            weaknesses = cve_data.get("cve", {}).get("weaknesses", [])
            cwe_id = ""
            if weaknesses:
                cwe_id = weaknesses[0].get("description", [{}])[0].get("value", "")

            # Get CVSS metrics
            metrics = cve_data.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [])
            cvss_data = metrics[0].get("cvssData", {}) if metrics else {}

            # Create context for mitigation advice
            context = {
                "cve_id": cve_data.get("cve", {}).get("id", ""),
                "description": cve_data.get("cve", {}).get("descriptions", [{}])[0].get("value", ""),
                "cwe_id": cwe_id,
                "attack_vector": cvss_data.get("attackVector", ""),
                "severity": cvss_data.get("baseSeverity", "")
            }

            # Generate mitigation strategies based on vulnerability type
            mitigation_prompt = f"""
            Based on the following vulnerability information:
            CVE ID: {context['cve_id']}
            Description: {context['description']}
            CWE ID: {context['cwe_id']}
            Attack Vector: {context['attack_vector']}
            Severity: {context['severity']}

            Provide specific mitigation strategies including:
            1. Immediate actions to take
            2. Long-term preventive measures
            3. Best practices for prevention
            4. Technical recommendations
            5. Security controls to implement
            """

            # Get mitigation response from LLM
            response = Settings.llm.complete(mitigation_prompt)

            return {
                "vulnerability_context": context,
                "mitigation_advice": response.text,
                "references": [ref.get("url") for ref in cve_data.get("cve", {}).get("references", [])]
            }

        except Exception as e:
            return {"error": f"Error generating mitigation strategies: {str(e)}"}

    def verify_cve(self, cve_id: str):
        """Verify CVE and provide mitigation strategies"""
        try:
            # Query vector store
            vector_results = self.query_engine.query(f"Tell me about {cve_id}")
            # Fetch NVD data
            nvd_data = self.fetch_nvd_data(cve_id)
            print(nvd_data)
            if not vector_results and not nvd_data:
                return {
                    "status": "error",
                    "message": f"No information found for {cve_id}"
                }

            # Get mitigation strategies
            mitigation_info = self.get_mitigation_strategies(nvd_data) if nvd_data else None

            # Combine all information
            verification_result = {
                "cve_id": cve_id,
                "vector_store_data": str(vector_results) if vector_results else None,
                "nvd_data": nvd_data,
                "mitigation": mitigation_info,
                "verification_status": "verified" if vector_results and nvd_data else "partial",
                "confidence_score": 1.0 if vector_results and nvd_data else 0.5
            }

            return verification_result

        except Exception as e:
            return {
                "status": "error",
                "message": f"Error during verification: {str(e)}"
            }

    async def process_technology_query(self, query: str):
        """Process natural language query about technology vulnerabilities"""
        try:
            # First, search for relevant CVEs in Pinecone
            vector_search_prompt = f"""
            Find CVEs related to the following technology or scenario:
            {query}
            Include specific CVE IDs and their descriptions.
            """

            # Get relevant CVEs from vector store
            vector_results = self.technology_query_engine.query(vector_search_prompt)

            # Extract CVE IDs from vector results
            relevant_cves = self.extract_cves_from_response(str(vector_results))

            # Create context from vector results
            technology_context = str(vector_results)

            # Enhanced prompt incorporating vector search results
            enhanced_prompt = f"""
            Based on the query: "{query}"

            Found relevant vulnerabilities:
            {technology_context}

            Please provide a comprehensive analysis including:
            1. Overview of security risks for the specified technology
            2. Analysis of the identified CVEs and their impact
            3. Specific mitigation strategies for each vulnerability
            4. General security best practices for this technology

            Focus on these specific CVEs: {', '.join(relevant_cves)}
            """

            # Get agent response
            agent_response = await self.agent.aquery(enhanced_prompt)

            # Get detailed information for each CVE
            detailed_info = []
            for cve_id in relevant_cves:
                nvd_data = self.fetch_nvd_data(cve_id)
                if nvd_data:
                    mitigation = self.get_mitigation_strategies(nvd_data)
                    detailed_info.append({
                        "cve_id": cve_id,
                        "cve_data": nvd_data,
                        "mitigation": mitigation,
                        "vector_store_info": self.get_vector_store_info(cve_id)
                    })

            return {
                "query": query,
                "technology_analysis": str(agent_response),
                "vector_store_results": str(vector_results),
                "relevant_cves": relevant_cves,
                "detailed_vulnerabilities": detailed_info
            }

        except Exception as e:
            return {
                "status": "error",
                "message": f"Error processing query: {str(e)}"
            }

    def get_vector_store_info(self, cve_id: str):
        """Get specific information about a CVE from vector store"""
        try:
            cve_query = self.query_engine.query(f"Tell me specifically about {cve_id}")
            return str(cve_query)
        except Exception:
            return None

    def extract_cves_from_response(self, response: str):
        """Extract CVE IDs from the response text"""
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        return list(set(re.findall(cve_pattern, response)))


def format_technology_response(response_data):
    """Format the technology analysis response"""
    if not response_data:
        return ""

    formatted_response = f"""
    ## Technology Security Analysis
    {response_data.get('technology_analysis')}

    ## Identified CVEs and Vulnerabilities
    """

    for vuln in response_data.get('detailed_vulnerabilities', []):
        cve_data = vuln.get('cve_data', {}).get('cve', {})
        metrics = cve_data.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {})

        formatted_response += f"""
        ### {vuln.get('cve_id', 'Unknown CVE')}
        **Severity**: {metrics.get('baseSeverity', 'Unknown')}
        **Attack Vector**: {metrics.get('attackVector', 'Unknown')}
        **Impact Score**: {metrics.get('baseScore', 'Unknown')}

        **Description**:
        {cve_data.get('descriptions', [{}])[0].get('value', 'No description available')}

        **Vector Store Analysis**:
        {vuln.get('vector_store_info', 'No additional information available')}

        **Mitigation Strategies**:
        {vuln.get('mitigation', {}).get('mitigation_advice', 'No mitigation advice available')}

        **References**:
        """

        for ref in cve_data.get('references', []):
            formatted_response += f"- {ref.get('url', '')}\n"

    return formatted_response


def format_response(response_data):
    """Format the verification and mitigation response"""
    if not response_data:
        return ""

    formatted_response = f"""
    ## CVE Information
    **CVE ID**: {response_data.get('cve_id')}
    **Verification Status**: {response_data.get('verification_status')}
    **Confidence Score**: {response_data.get('confidence_score') * 100}%

    ## Description
    {response_data.get('nvd_data', {}).get('cve', {}).get('descriptions', [{}])[0].get('value', 'No description available')}

    ## Mitigation Strategies
    """

    if response_data.get('mitigation'):
        mitigation = response_data['mitigation']
        formatted_response += f"""
        {mitigation.get('mitigation_advice')}

        ## Additional References
        """
        for ref in mitigation.get('references', []):
            formatted_response += f"- {ref}\n"

    return formatted_response


def format_langchain_response(response_data):
    """Format the LangChain response"""
    if not response_data:
        return ""

    formatted_response = f"""
    **Assistant**: {response_data['answer']}

    **Sources**:
    """

    for doc in response_data.get('source_documents', []):
        metadata = doc.metadata
        formatted_response += f"""
        ---
        **CVE ID**: {metadata.get('cve_id', 'N/A')}
        **Severity**: {metadata.get('severity', 'N/A')}
        **CVSS Score**: {metadata.get('score', 'N/A')}
        **Published**: {metadata.get('published_date', 'N/A')}
        """

    return formatted_response


def main():
    st.title("Technology Vulnerability Analysis Assistant")

    if 'agent' not in st.session_state:
        st.session_state.agent = CVEVerificationAgent()
    if 'langchain_agent' not in st.session_state:
        st.session_state.langchain_agent = CVEChatbot()

    # Add tabs for different query types
    # tab1, tab2, tab3 = st.tabs(["Technology Query", "CVE Lookup", "Technology Query with Langchain"])
    tab2, tab3 = st.tabs(["CVE Lookup", "Technology Query with Langchain"])

    # with tab1:
    #     query = st.text_area(
    #         "Describe your technology or security concern:",
    #         placeholder="Example: What are the security vulnerabilities in MongoDB and how can I protect against them?"
    #     )
    #     if st.button("Analyze Technology"):
    #         if query:
    #             with st.spinner("Analyzing technology vulnerabilities..."):
    #                 result = asyncio.run(st.session_state.agent.process_technology_query(query))
    #                 st.markdown(format_technology_response(result))
    #         else:
    #             st.warning("Please enter a technology query")

    with tab2:
        cve_id = st.text_input("Enter CVE ID (e.g., CVE-2024-1234):")
        if st.button("Analyze CVE"):
            if cve_id:
                with st.spinner("Analyzing vulnerability..."):
                    result = st.session_state.agent.verify_cve(cve_id)
                    st.markdown(format_response(result))
            else:
                st.warning("Please enter a CVE ID")
    with tab3:
        st.subheader("Technology Query with LangChain")

        # Chat input
        user_query = st.text_input(
            "Ask about CVEs:",
            key="langchain_input",
            placeholder="Ask any question about CVEs, vulnerabilities, or security concerns..."
        )

        # Search button for LangChain query
        if st.button("Send", key="langchain_send"):
            if user_query:
                with st.spinner("Processing your query..."):
                    # Get response from LangChain agent
                    response_data = st.session_state.langchain_agent.get_response(user_query)

                    if response_data:
                        st.markdown("### Response")
                        st.markdown(f"**Query**: {user_query}")
                        st.markdown(format_langchain_response(response_data))
            else:
                st.warning("Please enter a query.")


if __name__ == "__main__":
    main()
