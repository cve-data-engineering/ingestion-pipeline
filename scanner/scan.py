import json
import subprocess
import logging
from logging.handlers import TimedRotatingFileHandler


# Set up logging with rotation at midnight and keeping 7 days history
logger = logging.getLogger("ChatCVELogger")
logger.setLevel(logging.INFO)
handler = TimedRotatingFileHandler('ChatCVE_logs.log', when="midnight", interval=1, backupCount=7)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y%m%d%H%M%S')
handler.setFormatter(formatter)
logger.addHandler(handler)


class ContainerAnalyzer:
    def __init__(self):
        self.vulnerability_data = {}
        self.sbom_data = {}

    def analyze_image(self, image_name):
        # Generate SBOM using Syft
        sbom_result = syft_scan(image_name)
        if not sbom_result:
            print(sbom_result)
            return False
        self.sbom_data[image_name] = sbom_result

        # Scan for vulnerabilities using Grype
        vuln_result = grype_scan(image_name)
        if not vuln_result:
            print(vuln_result)
            return False
        self.vulnerability_data[image_name] = vuln_result

        return True

    def get_vulnerability_info(self, image_name, cve_id=None):
        if image_name not in self.vulnerability_data:
            return None

        if cve_id:
            # Return specific CVE info
            vulns = self.vulnerability_data[image_name].get('matches', [])
            return [v for v in vulns if v.get('vulnerability', {}).get('id') == cve_id]

        return self.vulnerability_data[image_name]

    def list_vulnerabilities(self, image_name):
        if image_name not in self.vulnerability_data:
            return []

        matches = self.vulnerability_data[image_name].get('matches', [])

        # Filter and return only CVE IDs that start with 'CVE'
        cve_list = []
        for match in matches:
            vuln_id = match.get('vulnerability', {}).get('id')
            if vuln_id and vuln_id.startswith('CVE'):
                cve_list.append(vuln_id)

        return cve_list


def syft_scan(image):
    syft_executable = '/usr/local/bin/syft'  # Default path after installation
    try:
        result = subprocess.run(
            [syft_executable, 'scan', f'registry:{image}', '--output', 'cyclonedx-json'],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            logger.error(f"Error executing syft command on image: {image}: {result.stderr.strip()}")
            return None
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing JSON output for image: {image}: {e}")
        return None


def grype_scan(image):
    try:
        result = subprocess.run(
            ['grype', f'registry:{image}', '-o', 'json'],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            logger.error(f"Error executing grype command on image: {image}: {result.stderr.strip()}")
            return None
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing JSON output for image: {image}: {e}")
        return None


def main():
    # Initialize the analyzer
    analyzer = ContainerAnalyzer()

    # Specify the image to analyze
    image_name = "public.ecr.aws/eks-distro/kubernetes-csi/node-driver-registrar:v2.8.0-eks-1-27-4"  # Example image

    # Analyze the image
    print(f"Analyzing image: {image_name}")
    if analyzer.analyze_image(image_name):
        # Get list of vulnerabilities
        vulnerabilities = analyzer.list_vulnerabilities(image_name)

        # Print vulnerabilities in a formatted way
        print("\nVulnerabilities found:")
        print("-" * 80)
        for vuln in vulnerabilities:
            print(f"""
        CVE ID: {vuln['cve_id']}
        Severity: {vuln['severity']}
        Package: {vuln['package']} (version: {vuln['version']})
        Description: {vuln['description']}
        """)
    else:
        print("Failed to analyze image")


if __name__ == "__main__":
    main()
