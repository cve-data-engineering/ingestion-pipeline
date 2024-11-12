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
            api_key=os.getenv("OPENAI_API_KEY")
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


def main():
    st.title("CVE Intelligence and Mitigation Assistant")

    if 'agent' not in st.session_state:
        st.session_state.agent = CVEVerificationAgent()

    cve_id = st.text_input("Enter CVE ID (e.g., CVE-2024-1234):")

    if st.button("Analyze"):
        if cve_id:
            with st.spinner("Analyzing vulnerability and generating recommendations..."):
                result = st.session_state.agent.verify_cve(cve_id)
                st.markdown(format_response(result))
        else:
            st.warning("Please enter a CVE ID")


if __name__ == "__main__":
    main()