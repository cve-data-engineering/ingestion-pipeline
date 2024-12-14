<p align="center">
    <img src="https://raw.githubusercontent.com/PKief/vscode-material-icon-theme/ec559a9f6bfd399b82bb44393651661b08aaf7ba/icons/folder-markdown-open.svg" align="center" width="30%">
</p>
<p align="center"><h1 align="center">INGESTION-PIPELINE</h1></p>
<p align="center">
</p>
<p align="center">
	<!-- local repository, no metadata badges. --></p>
<p align="center">Built with the tools and technologies:</p>
<p align="center">
	<img src="https://img.shields.io/badge/Streamlit-FF4B4B.svg?style=default&logo=Streamlit&logoColor=white" alt="Streamlit">
	<img src="https://img.shields.io/badge/.ENV-ECD53F.svg?style=default&logo=dotenv&logoColor=black" alt=".ENV">
	<img src="https://img.shields.io/badge/Docker-2496ED.svg?style=default&logo=Docker&logoColor=white" alt="Docker">
	<img src="https://img.shields.io/badge/Python-3776AB.svg?style=default&logo=Python&logoColor=white" alt="Python">
	<img src="https://img.shields.io/badge/Apache%20Airflow-017CEE.svg?style=default&logo=Apache-Airflow&logoColor=white" alt="Apache%20Airflow">
	<img src="https://img.shields.io/badge/GitHub%20Actions-2088FF.svg?style=default&logo=GitHub-Actions&logoColor=white" alt="GitHub%20Actions">
</p>
<br>

##  Table of Contents

- [ Overview](#-overview)
- [ Features](#-features)
- [ Project Structure](#-project-structure)
  - [ Project Index](#-project-index)
- [ Getting Started](#-getting-started)
  - [ Prerequisites](#-prerequisites)
  - [ Installation](#-installation)
  - [ Usage](#-usage)
  - [ Testing](#-testing)
- [ Project Roadmap](#-project-roadmap)
- [ Contributing](#-contributing)
- [ License](#-license)
- [ Acknowledgments](#-acknowledgments)

---

##  Overview

An LLM powered system that detects CVEs in container images and offers a chatbot for insights into vulnerabilities and mitigation strategies

---

##  Project Structure

```sh
└── ingestion-pipeline/
    ├── .github
    │   └── workflows
    ├── ChatCVE_logs.log
    ├── ChatCVE_logs.log.2024-12-10
    ├── README.md
    ├── __pycache__
    │   ├── download.cpython-311.pyc
    │   ├── processor.cpython-311.pyc
    │   └── uploader.cpython-311.pyc
    ├── airflow
    │   ├── Dockerfile
    │   ├── __init__.py
    │   ├── bin
    │   ├── dags
    │   ├── docker-compose.yaml
    │   └── requirements.txt
    ├── artifacts
    │   ├── image-urls.zip
    │   └── image_urls.txt
    ├── chatbot
    │   ├── .env
    │   ├── README.md
    │   ├── __pycache__
    │   ├── llama_index_chatbot.py
    │   └── main.py
    ├── chatbot_pg
    │   ├── .env
    │   ├── __pycache__
    │   ├── db.py
    │   └── main.py
    ├── consumer
    │   ├── .dockerignore
    │   ├── .env
    │   ├── Dockerfile
    │   ├── README.md
    │   ├── __pycache__
    │   ├── consumer.py
    │   ├── main.py
    │   ├── requirements.txt
    │   ├── sample.env
    │   └── snowflake_uploader.py
    ├── demo_examples
    │   ├── Dockerfile_busybox_patch
    │   └── Dockerfile_busybox_vul
    ├── download.py
    ├── extracted_files
    │   └── deltaCves
    ├── images.txt
    ├── lc.py
    ├── llama-chatbot
    │   ├── .env
    │   ├── eval.py
    │   └── main.py
    ├── processor.py
    ├── requirements.txt
    └── scanner
        ├── ChatCVE_logs.log
        ├── __pycache__
        └── scan.py
```

---
##  Getting Started

###  Prerequisites

Before getting started with ingestion-pipeline, ensure your runtime environment meets the following requirements:

- **Programming Language:** Error detecting primary_language: {'txt': 5, '2024-12-10': 1, 'py': 16, 'yaml': 1, 'json': 714, 'yml': 1}
- **Package Manager:** Pip
- **Container Runtime:** Docker


###  Installation

Install ingestion-pipeline using one of the following methods:

**Build from source:**

1. Clone the ingestion-pipeline repository:
```sh
❯ git clone git@github.com:cve-data-engineering/ingestion-pipeline.git
```

2. Navigate to the project directory:
```sh
❯ cd ingestion-pipeline
```

3. Install the project dependencies:


```sh
❯ pip install -r requirements.txt
```


---

##  Contributing

- **💬 [Join the Discussions](https://LOCAL//ingestion-pipeline/discussions)**: Share your insights, provide feedback, or ask questions.
- **🐛 [Report Issues](https://LOCAL//ingestion-pipeline/issues)**: Submit bugs found or log feature requests for the `ingestion-pipeline` project.
- **💡 [Submit Pull Requests](https://LOCAL//ingestion-pipeline/blob/main/CONTRIBUTING.md)**: Review open PRs, and submit your own PRs.

<details closed>
<summary>Contributing Guidelines</summary>

1. **Fork the Repository**: Start by forking the project repository to your LOCAL account.
2. **Clone Locally**: Clone the forked repository to your local machine using a git client.
   ```sh
   git clone git@github.com:cve-data-engineering/ingestion-pipeline.git
   ```
3. **Create a New Branch**: Always work on a new branch, giving it a descriptive name.
   ```sh
   git checkout -b new-feature-x
   ```
4. **Make Your Changes**: Develop and test your changes locally.
5. **Commit Your Changes**: Commit with a clear message describing your updates.
   ```sh
   git commit -m 'Implemented new feature x.'
   ```
6. **Push to LOCAL**: Push the changes to your forked repository.
   ```sh
   git push origin new-feature-x
   ```
7. **Submit a Pull Request**: Create a PR against the original project repository. Clearly describe the changes and their motivations.
8. **Review**: Once your PR is reviewed and approved, it will be merged into the main branch. Congratulations on your contribution!
</details>

<details closed>
<summary>Contributor Graph</summary>
<br>
<p align="left">
   <a href="https://LOCAL{//ingestion-pipeline/}graphs/contributors">
      <img src="https://contrib.rocks/image?repo=/ingestion-pipeline">
   </a>
</p>
</details>

---

