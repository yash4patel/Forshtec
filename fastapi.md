# VirusTotal API Integration - API Documentation

## Overview

This application provides REST API endpoints to scan domains, IP addresses, and files using VirusTotal's threat intelligence services. It stores analysis results in a PostgreSQL database for later retrieval.

---

## Setup

1. **Install requirements:**

   ```bash
   pip install -r requirements.txt
   ```

2. **Set up a `.env` file with your VirusTotal API key:**

   ```env
   API_KEY=your_virustotal_api_key
   ```

3. **Start the server:**

   ```bash
   uvicorn push_data:app --reload
   ```

---

## API Endpoints

### Push Data Endpoints

These endpoints submit items to VirusTotal for analysis and store the results.

---

#### **Domain Analysis**

- **GET** `/domain/{domain_name}`  
  Analyzes a domain and saves results to the database.

- **Path Parameters:**
  - `domain_name`: The domain to analyze (e.g., `example.com`)

- **Response:** Domain analysis data containing reputation scores and security information

- **Example:**

  ```bash
  curl -X GET "http://localhost:8000/domain/example.com"
  ```

---

#### **IP Address Analysis**

- **GET** `/ip/{ip}`  
  Analyzes an IP address and saves results to the database.

- **Path Parameters:**
  - `ip`: The IP address to analyze (e.g., `8.8.8.8`)

- **Response:** IP analysis data containing reputation scores and security information

- **Example:**

  ```bash
  curl -X GET "http://localhost:8000/ip/8.8.8.8"
  ```

---

#### **File Upload Form**

- **GET** `/file/upload`  
  Returns an HTML form for uploading files for analysis.

- **Response:** HTML form for file uploading

- **Example:**

  ```bash
  curl -X GET "http://localhost:8000/file/upload"
  ```

---

#### **File Analysis**

- **POST** `/file/file-id/`  
  Uploads a file to VirusTotal for analysis and saves results to the database.

- **Request:** Multipart form data with file  
  - `file`: The file to analyze

- **Response:** JSON containing file ID and success message

- **Example:**

  ```bash
  curl -X POST "http://localhost:8000/file/file-id/" -F "file=@/path/to/file.exe"
  ```

---

### Get Data Endpoints

These endpoints retrieve previously analyzed data from the database.

---

#### **Get Domain Analysis**

- **GET** `/get/domain/{domain_name}`  
  Retrieves stored analysis data for a domain.

- **Path Parameters:**
  - `domain_name`: The domain to retrieve data for

- **Response:** Domain analysis data from the database

- **Example:**

  ```bash
  curl -X GET "http://localhost:8000/get/domain/example.com"
  ```

---

#### **Get IP Analysis**

- **GET** `/get/ip/{ip}`  
  Retrieves stored analysis data for an IP address.

- **Path Parameters:**
  - `ip`: The IP address to retrieve data for

- **Response:** IP analysis data from the database

- **Example:**

  ```bash
  curl -X GET "http://localhost:8000/get/ip/8.8.8.8"
  ```

---

#### **Get File Analysis**

- **GET** `/get/file/{file_hash}`  
  Retrieves stored analysis data for a file by its hash.

- **Path Parameters:**
  - `file_hash`: The SHA256 or MD5 hash of the file

- **Response:** File analysis data from the database

- **Example:**

  ```bash
  curl -X GET "http://localhost:8000/get/file/a1b2c3d4e5f6..."
  ```

---

## Response Models

---

### **Domain Analysis Response**

```json
{
  "id": 1,
  "domain_id": 1,
  "creation_date": "2023-01-15T12:30:45",
  "last_update_date": "2023-05-20T08:15:30",
  "last_analysis_date": "2023-05-20T08:15:30",
  "harmless_count": 70,
  "malicious_count": 5,
  "suspicious_count": 2,
  "undetected_count": 10,
  "timeout_count": 0,
  "total_count": 87,
  "results": [...],
  "dns_records": [...],
  "certificates": [...],
  "categories": [...]
}
```

---

### **IP Analysis Response**

```json
{
  "id": 1,
  "ip": "8.8.8.8",
  "analyses": [
    {
      "id": 1,
      "ip_id": 1,
      "created_at": "2023-05-20T08:15:30",
      "as_owner": "Google LLC",
      "asn": 15169,
      "continent": "NA",
      "country": "US",
      "harmless_count": 75,
      "malicious_count": 0,
      "suspicious_count": 0,
      "undetected_count": 15,
      "timeout_count": 0,
      "results": [...],
      "certificates": [...]
    }
  ]
}
```

---

### **File Analysis Response**

```json
{
  "analysis_date": "2023-05-20T08:15:30",
  "first_submission_date": "2023-01-10T14:22:05",
  "last_analysis_date": "2023-05-20T08:15:30",
  "harmless_count": 65,
  "malicious_count": 10,
  "suspicious_count": 5,
  "undetected_count": 10,
  "timeout_count": 0,
  "results": [...],
  "sigma_analyses": [...]
}
```

---

## Error Responses

The API returns standard HTTP status codes:

- **200 OK**: Successful operation  
- **404 Not Found**: Resource not found  
- **500 Internal Server Error**: Server-side error

**Error response example:**

```json
{
  "detail": "Domain not found"
}
```
