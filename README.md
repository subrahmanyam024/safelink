SafeLink - URL Security Checker
SafeLink is a web application designed to analyze the security of URLs by checking for malware, phishing, and other threats using multiple APIs. It provides a security score and detailed reports to help users evaluate URL safety.


Features

->URL Structure Analysis: Examines URL patterns for suspicious characteristics.
->Malware Detection: Scans URLs using the VirusTotal API.
->Phishing Protection: Checks for phishing threats via Google Safe Browsing API.
->SSL Validation: Assesses SSL certificate quality with SSL Labs API.
->Redirect Tracking: Follows URL redirects to identify final destinations.
->Single & Bulk URL Analysis: Supports checking one or multiple URLs.
->Security Score: Calculates a score (0-100) based on analysis results.
------------------------------------
Getting Started

Prerequisites

->Node.js (v18 or higher)
->npm (Node Package Manager)
->API keys for:
   ->VirusTotal (sign up at virustotal.com)
   ->Google Safe Browsing (get from Google Cloud Console)
   ->SSL Labs (free, no key required)

------------------------------------------

Installation

->Clone the repository:git clone https://github.com/subrahmanyam024/safelink
cd safelink


->Install dependencies:npm install 


->Configure API keys in config.js:const API_CONFIG = {
    VIRUSTOTAL: { key: 'your_virustotal_api_key', url: 'https://www.virustotal.com/vtapi/v2/url' },
    SAFE_BROWSING: { key: 'your_safe_browsing_api_key', url: 'https://safebrowsing.googleapis.com/v4/threatMatches:find' },
    SSL_LABS: { url: 'https://api.ssllabs.com/api/v3/analyze' }
};


Start the server:npm start


Open your browser and navigate to http://localhost:3000.

Usage

Single URL Check: Enter a URL (e.g., https://example.com) and click "Analyze URL(s)".
Bulk URL Check: Switch to "Bulk URLs" mode, enter multiple URLs (one per line), and analyze.
View results, including security score, safety level, and detailed findings.

Project Details
For a comprehensive guide on the project’s architecture, modules, tools, and development process, refer to PROJECT_GUIDE.md.
Contributing
Contributions are welcome! Please:

Fork the repository.
Create a feature branch (git checkout -b feature/your-feature).
Commit changes (git commit -m 'Add your feature').
Push to the branch (git push origin feature/your-feature).
Open a pull request.

License
Licensed under the ISC License. See LICENSE for details.
Acknowledgments

APIs: VirusTotal, Google Safe Browsing, SSL Labs
Technologies: Node.js, Express.js, Fetch API
Authors: S. Nandini, T. Subrahmanyam

Version History

1.0.0: Initial release with single and bulk URL analysis, API integration, and security scoring.

