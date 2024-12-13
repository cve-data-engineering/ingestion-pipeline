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
import time
import threading
import zipfile
from dotenv import load_dotenv

from chatbot.main import CVEChatbot
from scanner.scan import ContainerAnalyzer

load_dotenv()
# Global variable to store image URLs
image_urls = []

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
            # Calculate base confidence score
            base_confidence_score = self.calculate_confidence_score(vector_results, nvd_data)
            # Calculate LLM-based confidence score
            llm_confidence_score = self.assess_verification_with_llm(vector_results, nvd_data)
            # Combine scores with weights (70% base, 30% LLM)
            final_confidence_score = round(0.7 * base_confidence_score + 0.3 * llm_confidence_score, 2)

            # Get mitigation strategies
            mitigation_info = self.get_mitigation_strategies(nvd_data) if nvd_data else None

            # Combine all information
            verification_result = {
                "cve_id": cve_id,
                "vector_store_data": str(vector_results) if vector_results else None,
                "nvd_data": nvd_data,
                "mitigation": mitigation_info,
                "verification_status": "verified" if vector_results and nvd_data else "partial",
                "confidence_score": final_confidence_score
            }

            return verification_result

        except Exception as e:
            return {
                "status": "error",
                "message": f"Error during verification: {str(e)}"
            }


    def calculate_confidence_score(self, vector_results, nvd_data):
        """Calculate base confidence score"""
        base_score = 0.5

        if vector_results:
            base_score += 0.25

        if nvd_data:
            key_fields = ['vulnerabilities', 'descriptions', 'metrics']
            completeness_score = sum(1 for field in key_fields if field in nvd_data) / len(key_fields)
            base_score += completeness_score * 0.25

        return min(1.0, max(0.0, base_score))

    def assess_verification_with_llm(self, vector_results, nvd_data):
        """Calculate LLM-based confidence score"""
        vector_score = len(str(vector_results).split()) / 100 if vector_results else 0
        nvd_score = len(str(nvd_data).split()) / 100 if nvd_data else 0

        combined_score = 0.6 * vector_score + 0.4 * nvd_score
        return min(1.0, max(0.0, combined_score))

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


def fetch_workflow_id(repo, token, workflow_name):
    """Fetch the workflow ID based on the workflow name."""
    workflows_url = f"https://api.github.com/repos/{repo}/actions/workflows"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    response = requests.get(workflows_url, headers=headers)
    response.raise_for_status()

    workflows = response.json()["workflows"]
    for workflow in workflows:
        if workflow["name"] == workflow_name or workflow["path"].endswith(workflow_name):
            return workflow["id"]
    
    raise ValueError(f"Workflow '{workflow_name}' not found in repository '{repo}'.")

def fetch_latest_successful_run(repo, token, workflow_id):
    """Fetch the latest successful run for a specific workflow."""
    runs_url = f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_id}/runs"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    response = requests.get(runs_url, headers=headers)
    response.raise_for_status()

    runs = response.json()["workflow_runs"]
    for run in runs:
        if run["conclusion"] == "success":
            return run["id"]
    
    raise ValueError("No successful runs found for the specified workflow.")

def fetch_artifact(repo, token, run_id, artifact_name, output_dir="artifacts", output_file="image_urls.txt"):
    """Fetch and download a specific artifact from a workflow run."""
    artifacts_url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/artifacts"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    response = requests.get(artifacts_url, headers=headers)
    response.raise_for_status()

    artifacts = response.json()["artifacts"]
    for artifact in artifacts:
        if artifact["name"] == artifact_name:
            download_url = artifact["archive_download_url"]
            artifact_response = requests.get(download_url, headers=headers)
            artifact_response.raise_for_status()
            
            
            # Save the downloaded ZIP file
            zip_file_path = f"{output_dir}/{artifact_name}.zip"
            os.makedirs(output_dir, exist_ok=True)
            with open(zip_file_path, "wb") as zip_file:
                zip_file.write(artifact_response.content)

            print(f"Artifact '{artifact_name}' downloaded as ZIP to {zip_file_path}.")

            # Unzip the file
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                zip_ref.extractall(output_dir)

            print(f"Artifact '{artifact_name}' unzipped to {output_dir}.")

            # Check if the expected file exists
            extracted_file_path = os.path.join(output_dir, output_file)
            if os.path.exists(extracted_file_path):
                print(f"File '{output_file}' is available for use.")
            else:
                print(f"Expected file '{output_file}' not found in the artifact.")
            return extracted_file_path
    
    raise ValueError(f"Artifact '{artifact_name}' not found in the run.")

def download_latest_artifact(token=os.getenv("GITHUB_TOKEN"), repo="cve-data-engineering/ingestion-pipeline", workflow_name="Build and List Demo Docker Images", artifact_name="image-urls", output_file="image_urls.txt", output_dir="artifacts"):
    """Fetch and download the artifact of the latest successful workflow run."""
    try:
        # Step 1: Fetch workflow ID
        workflow_id = fetch_workflow_id(repo, token, workflow_name)
        print(f"Workflow ID for '{workflow_name}': {workflow_id}")

        # Step 2: Fetch the latest successful run ID
        run_id = fetch_latest_successful_run(repo, token, workflow_id)
        print(f"Latest successful run ID: {run_id}")

        # Step 3: Fetch and download the artifact
        # fetch_artifact(repo, token, run_id, artifact_name, output_file)
        
        # Step 3: Fetch, unzip, and extract the artifact
        extracted_file_path = fetch_artifact(
            repo=repo,
            token=token,
            run_id=run_id,
            artifact_name=artifact_name,
            output_file=output_file,
            output_dir=output_dir
        )
        
        # Step 4: Process the extracted file
        if extracted_file_path and os.path.exists(extracted_file_path):
            with open(extracted_file_path, "r") as file:
                image_urls = [line.strip() for line in file.readlines()]
                print(f"Processed image URLs: {image_urls}")
            return image_urls
        else:
            raise FileNotFoundError(f"Extracted file '{output_file}' not found in directory '{output_dir}'.")
        
    except Exception as e:
        print(f"Error: {e}")
        

        
        
# # Function to fetch and update image URLs
# def update_image_urls(file_path="image_urls.txt"):
#     global image_urls
#     try:
#         with open(file_path, "r") as file:
#             # Read and update the global image_urls list
#             image_urls = [line.strip() for line in file.readlines()]
#     except FileNotFoundError:
#         print("image_urls.txt not found. Retrying...")
#     except Exception as e:
#         print(f"Error reading image_urls.txt: {e}")
        
# # Function to fetch the latest artifact dynamically
# def download_latest_image_urls(repo, token, workflow_name, artifact_name, output_file="image_urls.txt"):
#     try:
#         # GitHub API URL to list workflow runs
#         workflows_url = f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_name}/runs"

#         # Request headers with authorization
#         headers = {
#             "Authorization": f"Bearer {token}",
#             "Accept": "application/vnd.github.v3+json"
#         }

#         # Fetch the list of workflow runs
#         response = requests.get(workflows_url, headers=headers)
#         response.raise_for_status()
#         runs = response.json()["workflow_runs"]

#         # Find the latest successful run
#         latest_run = next((run for run in runs if run["conclusion"] == "success"), None)
#         if not latest_run:
#             print("No successful workflow runs found.")
#             return

#         # Get the artifacts for the latest run
#         run_id = latest_run["id"]
#         artifacts_url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/artifacts"
#         artifacts_response = requests.get(artifacts_url, headers=headers)
#         artifacts_response.raise_for_status()
#         artifacts = artifacts_response.json()["artifacts"]

#         # Find the artifact by name
#         artifact = next((a for a in artifacts if artifact_name in a["name"]), None)
#         if not artifact:
#             print(f"Artifact '{artifact_name}' not found in the latest run.")
#             return

#         # Download the artifact
#         download_url = artifact["archive_download_url"]
#         artifact_response = requests.get(download_url, headers=headers)
#         artifact_response.raise_for_status()

#         # Save the artifact locally
#         with open(output_file, "wb") as file:
#             file.write(artifact_response.content)

#         print(f"Downloaded and updated {output_file}.")
#     except Exception as e:
#         print(f"Error downloading artifact: {e}")

# # Background job to periodically fetch the latest artifact
# def background_fetch_urls(interval=60, repo="cve-data-engineering/ingestion-pipeline", workflow_name="build-and-push.yml", artifact_name="image-urls"):
#     while True:
#         # Replace with your GitHub token
#         github_token = os.getenv("GITHUB_TOKEN")
#         if not github_token:
#             print("GitHub token not found in environment variables.")
#             return

#         download_latest_image_urls(repo, github_token, workflow_name, artifact_name)
#         # Update the image_urls list
#         update_image_urls()

#         time.sleep(interval)

        
def main():
    # Start a background thread to fetch URLs periodically
    # threading.Thread(target=download_latest_artifact, daemon=True).start()
    
    st.title("Technology Vulnerability Analysis Assistant")

    if 'agent' not in st.session_state:
        st.session_state.agent = CVEVerificationAgent()
    if 'langchain_agent' not in st.session_state:
        st.session_state.langchain_agent = CVEChatbot()
    if 'container_analyzer' not in st.session_state:
        st.session_state.container_analyzer = ContainerAnalyzer()

    # Add tabs for different query types
    tab1, tab2, tab3 = st.tabs(
        ["Container Scanner", "CVE Lookup", "Technology Query with LangChain"])

    with tab1:
        st.subheader("Container Image Vulnerability Scanner")
        
        # Fetch and process the latest artifact
        image_urls = download_latest_artifact()
        
        # Dropdown for selecting a pre-defined image
        selected_image = st.selectbox(
            "Select a Docker image from the list:",
            options=["Enter Manually"] + image_urls,
            help="Select an image from the list or choose 'Enter Manually' to input a custom image URL."
        )
        
        # Input field for manual image entry, shown only if 'Enter Manually' is selected
        image_name = ""
        if selected_image == "Enter Manually":
            image_name = st.text_input(
                "Enter container image name:",
                placeholder="Example: python:3.9-slim"
            )
        else:
            image_name = selected_image

        # # Input for container image
        # image_name = st.text_input(
        #     "Enter container image name:",
        #     placeholder="Example: python:3.9-slim"
        # )

        if st.button("Scan Container"):
            if image_name:
                with st.spinner("Scanning container image..."):
                    # Analyze the image
                    if st.session_state.container_analyzer.analyze_image(image_name):
                        # Get vulnerabilities
                        vulnerabilities = st.session_state.container_analyzer.list_vulnerabilities(image_name)

                        if vulnerabilities:
                            st.success(f"Found {len(vulnerabilities)} CVEs in {image_name}")
                            st.markdown("### Vulnerabilities Found:")
                            for cve_id in vulnerabilities:
                                st.markdown(f"- {cve_id}")
                        else:
                            st.success("No vulnerabilities found in the image")
                    else:
                        st.error("Failed to analyze container image")
            else:
                st.warning("Please enter a container image name")

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
        user_query = st.text_input(
            "Ask about CVEs:",
            key="langchain_input",
            placeholder="Ask any question about CVEs, vulnerabilities, or security concerns..."
        )

        if st.button("Send", key="langchain_send"):
            if user_query:
                with st.spinner("Processing your query..."):
                    response_data = st.session_state.langchain_agent.get_response(user_query)
                    if response_data:
                        st.markdown("### Response")
                        st.markdown(f"**Query**: {user_query}")
                        st.markdown(format_langchain_response(response_data))
            else:
                st.warning("Please enter a query.")


if __name__ == "__main__":
    main()
