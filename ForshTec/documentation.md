# ForshTec Security Analysis Platform

## Overview

ForshTec is a Django-based security analysis platform that integrates with VirusTotal's API to provide comprehensive analysis for:

1. IP addresses
2. Domains
3. Files/malware

The platform allows users to submit requests for analysis, stores results in a database for future reference, and implements efficient caching mechanisms to reduce API calls and improve response times.

## System Architecture

The application is structured with three main Django apps:

- **IP**: Analysis of IP addresses
- **Domain**: Analysis of domain names
- **File**: Analysis of files for malware detection

Each app follows similar patterns with:
- API integration with VirusTotal
- Data models for storing analysis results
- Views for handling requests and responses
- URL routing for API endpoints

## Technical Stack

- **Backend**: Django + Django REST Framework
- **Database**: Django ORM (database agnostic)
- **Caching**: Django's cache framework
- **External API**: VirusTotal API v3
- **File Storage**: Django's default storage system

## Core Features

### 1. IP Address Analysis

#### Endpoints

- `GET /ip/<str:ip_address>/`: Analyze an IP address using VirusTotal
- `GET /ip/db/<str:ip_address>/`: Retrieve stored analysis for an IP address

#### Data Model

- `IPAddress`: Stores the IP address
- `IPAnalysis`: Stores analysis results
- `IPAnalysisResult`: Stores individual engine results
- `IPCertificate`: Stores SSL certificate information

### 2. Domain Analysis

#### Endpoints

- `GET /domain/virustotal/<str:domain_name>/`: Analyze a domain using VirusTotal
- `GET /domain/database/<str:domain_name>/`: Retrieve stored analysis for a domain
- `GET /domain/filter/`: Filter domains based on various criteria

#### Data Model

- `Domain`: Stores the domain name
- `DomainAnalysis`: Stores analysis results
- `DomainAnalysisResult`: Stores individual engine results
- `DomainCategory`: Stores domain categories
- `DomainCertificate`: Stores SSL certificate information
- `DomainDNSRecord`: Stores DNS records
- `SubjectAlternativeName`: Stores certificate SAN entries

### 3. File Analysis

#### Endpoints

- `GET /file/upload/`: Web interface for file upload
- `POST /file/file-analysis/`: Analyze a file using VirusTotal
- `GET /file/file-db/<str:file_hash>/`: Retrieve stored analysis for a file

#### Data Model

- `File`: Stores file metadata and hashes
- `FileAnalysis`: Stores analysis results
- `FileAnalysisResult`: Stores individual engine results
- `FileSigmaAnalysis`: Stores Sigma rule analysis results

## API Documentation

### IP Address Analysis

#### Get IP Analysis