# SafeLink Project Guide

This document provides a comprehensive overview of the **SafeLink** URL Security Checker project, including its purpose, architecture, required modules, tools, their functionality, and the development process. It is designed to help developers, contributors, and users understand the project and extend its functionality.

## Project Overview

**SafeLink** is a web application that evaluates the safety of URLs by analyzing their structure, checking for malware, phishing, and SSL certificate validity, and tracking redirects. It integrates with external APIs (VirusTotal, Google Safe Browsing, SSL Labs) to provide accurate security assessments and presents results with a security score (0-100) and detailed reports. The application supports both single and bulk URL analysis, making it versatile for individual users and batch processing.

### Objectives
- Enhance web safety by identifying malicious or risky URLs.
- Provide a user-friendly interface for URL analysis.
- Integrate reliable third-party APIs for robust security checks.
- Offer clear, actionable insights through security scores and reports.

## Project Architecture

SafeLink follows a client-server architecture with a frontend for user interaction and a backend for API handling and processing. Key components include:

- **Frontend** (`index.html`, `style.css`, `script.js`):
  - **HTML**: Defines the structure of the web interface, including input fields, result displays, and feature sections.
  - **CSS**: Styles the interface with a modern, responsive design using gradients, animations, and Tailwind-inspired aesthetics.
  - **JavaScript**: Handles user interactions, triggers API calls, and renders analysis results dynamically.
- **Backend** (`server.js`, `api-handler.js`, `config.js`):
  - **Node.js/Express Server**: Manages API requests, proxies calls to external APIs, and serves the frontend.
  - **API Handler**: Encapsulates logic for interacting with VirusTotal, Google Safe Browsing, and SSL Labs APIs.
  - **Configuration**: Stores API keys and settings.
- **Dependencies** (`package.json`): Lists required Node.js modules for server functionality.

## Required Modules

The project relies on Node.js modules to handle HTTP requests, API communication, and server setup. Below is a list of required modules, their versions, and purposes:

| Module       | Version | Purpose                                                                 |
|--------------|---------|-------------------------------------------------------------------------|
| `express`    | ^5.1.0  | Web framework for creating the server, handling routes, and serving files. |
| `cors`       | ^2.8.5  | Enables Cross-Origin Resource Sharing for API requests from the frontend. |
| `node-fetch` | ^3.3.2  | Provides a fetch API for making HTTP requests to external APIs.          |

### Installation
To install these modules, run:
```bash
npm install
```
This uses the `package.json` to fetch the specified versions.

## Tools and Their Functionality

SafeLink leverages several tools and APIs to deliver its functionality. Below is an explanation of each tool, why it’s used, and its role in the project:

### 1. Node.js
- **Purpose**: JavaScript runtime for running the backend server.
- **Why Used**: Enables server-side JavaScript, supports asynchronous operations, and integrates with npm for dependency management.
- **Functionality**: Executes `server.js` to host the application, handle API requests, and serve static files (`index.html`, `style.css`, `script.js`).

### 2. Express.js
- **Purpose**: Web framework for Node.js.
- **Why Used**: Simplifies server setup, routing, and middleware integration.
- **Functionality**: Defines API endpoints (e.g., `/api/virustotal/scan`, `/api/redirects`) and serves the frontend interface.

### 3. VirusTotal API
- **Purpose**: Scans URLs for malware and other threats.
- **Why Used**: Provides access to a database of security vendor reports, offering reliable malware detection.
- **Functionality**: Checks URLs for malicious content, returning a report with positives (threats detected) and total scans. Results influence the security score (e.g., 0 positives = +25 weight).

### 4. Google Safe Browsing API
- **Purpose**: Identifies phishing, malware, and unwanted software in URLs.
- **Why Used**: Google’s extensive threat database ensures accurate phishing detection.
- **Functionality**: Returns threat matches (e.g., `MALWARE`, `SOCIAL_ENGINEERING`), impacting the security score (e.g., phishing = -35 weight).

### 5. SSL Labs API
- **Purpose**: Assesses SSL/TLS certificate quality.
- **Why Used**: Validates encryption strength, crucial for secure connections.
- **Functionality**: Assigns a grade (A+ to F) to the SSL certificate, affecting the score (e.g., A+ = +20 weight, F = -15 weight).

### 6. node-fetch
- **Purpose**: Makes HTTP requests to external APIs.
- **Why Used**: Lightweight and compatible with Node.js for fetching API data.
- **Functionality**: Sends requests to VirusTotal, Google Safe Browsing, and SSL Labs APIs, retrieving JSON responses.

### 7. CORS
- **Purpose**: Allows cross-origin requests.
- **Why Used**: Enables the frontend (browser) to communicate with the backend server.
- **Functionality**: Configures the server to accept requests from `http://localhost:3000`.

## Project Functionality

SafeLink’s core functionality is divided into frontend and backend operations:

### Frontend
- **User Interface** (`index.html`, `style.css`):
  - Displays a header, input section (single/bulk URL), loading animation, result section, and feature overview.
  - Uses responsive design for mobile and desktop compatibility.
  - Animates the security score with a conic gradient circle.
- **User Interaction** (`script.js`):
  - Validates URLs (e.g., checks for `http://` or `https://`).
  - Toggles between single and bulk URL modes.
  - Triggers analysis via button click or Enter key.
  - Renders results with safety levels (Safe, Warning, Danger), scores, and detailed findings.
  - Handles bulk URL processing by iterating through inputs.

### Backend
- **Server** (`server.js`):
  - Hosts the application on `http://localhost:3000`.
  - Proxies API requests to avoid CORS issues and protect API keys.
  - Tracks redirects using the `fetch` API with `redirect: 'follow'`.
- **API Handler** (`api-handler.js`):
  - Manages API calls to VirusTotal, Google Safe Browsing, and SSL Labs.
  - Parses API responses into standardized result objects (type, icon, text, weight).
  - Implements fallback checks (e.g., basic HTTPS detection if SSL Labs fails).
- **Configuration** (`config.js`):
  - Stores API keys and URLs, with a `DEMO_MODE` flag for testing.

### Analysis Process
1. **Input**: User enters a URL (single) or multiple URLs (bulk).
2. **Redirect Check**: Tracks redirects to identify the final URL.
3. **URL Structure Analysis**: Checks for suspicious patterns (e.g., long domains, IP addresses).
4. **Phishing Detection**: Identifies phishing keywords and domain similarity to legitimate sites.
5. **API Checks**: Queries VirusTotal, Google Safe Browsing, and SSL Labs for threats and SSL quality.
6. **Scoring**: Calculates a security score (0-100) based on weighted results.
7. **Output**: Displays results with a safety level, score, and detailed findings.

## Development Process

The project was developed iteratively, with the following phases:

### 1. Planning
- **Objective**: Create a URL security checker with API integration.
- **Requirements**:
  - Support single and bulk URL analysis.
  - Integrate VirusTotal, Google Safe Browsing, and SSL Labs APIs.
  - Provide a user-friendly interface with security scores.
- **Tools Chosen**: Node.js, Express.js, and browser-based JavaScript for compatibility and scalability.

### 2. Design
- **Frontend**: Designed a responsive interface with HTML/CSS, focusing on usability and visual appeal.
- **Backend**: Planned a proxy server to handle API calls securely.
- **Scoring System**: Defined weights for each check (e.g., HTTPS = +15, malware = -30) to compute a 0-100 score.

### 3. Implementation
- **Frontend**:
  - Built `index.html` with sections for input, results, and features.
  - Styled with `style.css` using gradients and animations.
  - Wrote `script.js` for URL validation, API triggering, and result rendering.
- **Backend**:
  - Set up `server.js` with Express.js and CORS.
  - Created `api-handler.js` to manage API interactions.
  - Configured `config.js` for API keys and demo mode.
- **Integration**: Connected frontend to backend via fetch requests to `http://localhost:3000/api/*`.

### 4. Testing
- Tested single URL analysis with examples (e.g., `https://example.com`, `http://bit.ly/3example`).
- Verified bulk URL processing with multiple inputs.
- Checked API responses for accuracy and error handling.
- Ensured responsive design on mobile and desktop.

### 5. Finalization
- Fixed bugs (e.g., invalid URL handling, API rate limits).
- Optimized performance with delays between bulk URL checks.
- Documented the project in `README.md` and `PROJECT_GUIDE.md`.

## Extending the Project

To enhance SafeLink, consider the following:

- **History/Favorites**: Add local storage to save analyzed URLs.
- **PDF Reports**: Generate downloadable reports using a library like `pdfkit`.
- **Domain Age Check**: Integrate WHOIS API to assess domain registration age.
- **Real-Time Alerts**: Notify users of high-risk URLs via email or browser notifications.
- **Authentication**: Add user accounts for personalized settings.

## Troubleshooting

- **API Errors**: Ensure API keys in `config.js` are valid. Check API rate limits (e.g., VirusTotal’s free tier has restrictions).
- **CORS Issues**: Verify the server is running and CORS is enabled (`cors` module).
- **Server Not Starting**: Confirm Node.js is installed and run `npm install` to resolve missing dependencies.
- **UI Issues**: Test in modern browsers (Chrome, Firefox) and clear cache if styles don’t load.

## Authors
- **S. Nandini**
- **T. Subrahmanyam**

## Contact
For questions or contributions, reach out via GitHub issues or email (replace with your contact details).

This guide aims to make SafeLink accessible to all users and developers. Happy coding! 🚀