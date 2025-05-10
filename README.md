# ForshTec Security Analysis Platform

## Overview  
ForshTec is a powerful, Django-based security analysis platform that integrates with the VirusTotal API to deliver in-depth analysis of:  
- **IP Addresses**  
- **Domain Names**  
- **Files/Malware**  

The platform enables users to request analysis, stores the results for future reference, and incorporates efficient caching mechanisms to minimize API calls and optimize performance.

---

## System Architecture  

ForshTec is organized into three key Django applications:  

1. **IP**: Provides analysis for IP addresses  
2. **Domain**: Handles domain name analysis  
3. **File**: Focuses on file/malware detection  

Each application adheres to a consistent design pattern, featuring:  
- API integration with VirusTotal  
- Data models for storing analysis results  
- Views to manage requests and responses  
- URL routing for seamless API interactions  

---

## Technical Stack  

- **Backend**: Django + Django REST Framework  
- **Database**: Django ORM (supports multiple databases)  
- **Caching**: Django's built-in caching framework  
- **External API**: VirusTotal API v3  
- **File Storage**: Django's default storage system  

---

## Core Features  

### 1. IP Address Analysis  
**Endpoints:**  
- `GET /ip/<str:ip_address>/`: Analyze an IP address using VirusTotal  
- `GET /ip/db/<str:ip_address>/`: Retrieve stored analysis results for an IP address  

**Data Models:**  
- `IPAddress`: Holds the IP address data  
- `IPAnalysis`: Stores analysis results  
- `IPAnalysisResult`: Maintains individual engine results  
- `IPCertificate`: Records SSL certificate information  

---

### 2. Domain Analysis  
**Endpoints:**  
- `GET /domain/virustotal/<str:domain_name>/`: Analyze a domain using VirusTotal  
- `GET /domain/database/<str:domain_name>/`: Retrieve stored analysis results for a domain  
- `GET /domain/filter/`: Filter domains based on user-defined criteria  

**Data Models:**  
- `Domain`: Stores domain name data  
- `DomainAnalysis`: Saves analysis results  
- `DomainAnalysisResult`: Captures individual engine outcomes  
- `DomainCategory`: Contains domain category classifications  
- `DomainCertificate`: Stores SSL certificate details  
- `DomainDNSRecord`: Holds DNS record data  
- `SubjectAlternativeName`: Tracks certificate SAN entries  

---

### 3. File Analysis  
**Endpoints:**  
- `GET /file/upload/`: Web interface for file uploads  
- `POST /file/file-analysis/`: Analyze files using VirusTotal  
- `GET /file/file-db/<str:file_hash>/`: Retrieve stored file analysis results  

**Data Models:**  
- `File`: Holds file metadata and hashes  
- `FileAnalysis`: Stores file analysis results  
- `FileAnalysisResult`: Tracks individual engine outcomes  
- `FileSigmaAnalysis`: Maintains Sigma rule analysis data  

---

## Caching Mechanism  

ForshTec utilizes Django's caching framework to store frequently accessed data and reduce redundant API calls. This ensures a fast, efficient user experience without compromising accuracy.  

---

## API Documentation  

Detailed API documentation can be found in the `docs/` directory or by accessing the Swagger UI provided by the Django REST Framework.  

---

## E-R Diagram  

The entity-relationship diagram illustrates the relationships between models in the IP, Domain, and File apps.  

---

### Contributions  
We welcome contributions! Please see the `CONTRIBUTING.md` file for guidelines on how to contribute to this project.  

### License  
This project is licensed under the MIT License. See the `LICENSE` file for details.  

---
