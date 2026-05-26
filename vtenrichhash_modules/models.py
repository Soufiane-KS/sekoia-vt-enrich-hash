from pydantic.v1 import BaseModel, Field


class VtenrichhashModuleConfiguration(BaseModel):
    apikey: str = Field(..., description="VirusTotal API key")
