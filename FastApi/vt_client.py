import httpx
from fastapi import HTTPException
import logging
import asyncio

logger = logging.getLogger(__name__)

class VirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}
    
    async def get_domain_report(self, domain_name: str):
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.base_url}/domains/{domain_name}",
                    headers=self.headers,
                    timeout=10
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                logger.error(f"VT API error: {e.response.status_code}")
                raise HTTPException(
                    status_code=e.response.status_code,
                    detail="VirusTotal API error"
                )
            except Exception as e:
                logger.error(f"Connection error: {str(e)}")
                raise HTTPException(
                    status_code=503,
                    detail="Service unavailable"
                )

    async def get_ip_report(self, ip: str):
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.base_url}/ip_addresses/{ip}",
                    headers=self.headers,
                    timeout=10
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                logger.error(f"VT API error: {e.response.status_code}")
                raise HTTPException(
                    status_code=e.response.status_code,
                    detail="VirusTotal API error"
                )
            except Exception as e:
                logger.error(f"Connection error: {str(e)}")
                raise HTTPException(
                    status_code=503,
                    detail="Service unavailable"
                )

    async def submit_file(self, file_path: str, filename: str):
        """Submit a file for analysis to VirusTotal."""
        try:
            with open(file_path, "rb") as file:
                files = {"file": (filename, file)}
                
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        f"{self.base_url}/files",
                        headers=self.headers,
                        files=files,
                        timeout=30
                    )
                    response.raise_for_status()
                    return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"VT API error: {e.response.status_code}")
            raise HTTPException(
                status_code=e.response.status_code,
                detail="VirusTotal API error"
            )
        except Exception as e:
            logger.error(f"Error submitting file: {str(e)}")
            raise HTTPException(
                status_code=503,
                detail="Service unavailable"
            )

    async def get_file_report(self, file_id: str, max_attempts: int = 10, delay: int = 5):
        """Retrieve file analysis report."""
        async with httpx.AsyncClient() as client:
            for attempt in range(max_attempts):
                try:
                    response = await client.get(
                        f"{self.base_url}/analyses/{file_id}",
                        headers=self.headers,
                        timeout=10
                    )
                    response.raise_for_status()
                    data = response.json()
                    # print(data)

                    
                    if data["data"]["attributes"]["status"] == "completed":
                        return data
                    
                    logger.info(f"Attempt {attempt + 1}/{max_attempts}: Analysis not completed yet.")
                    await asyncio.sleep(delay)
                except httpx.HTTPStatusError as e:
                    logger.error(f"VT API error: {e.response.status_code}")
                    raise HTTPException(
                        status_code=e.response.status_code,
                        detail="VirusTotal API error"
                    )
                except Exception as e:
                    logger.error(f"Error retrieving file report: {str(e)}")
                    raise HTTPException(
                        status_code=503,
                        detail="Service unavailable"
                    )
            raise HTTPException(
                status_code=408,
                detail="Analysis report retrieval timed out"
            )