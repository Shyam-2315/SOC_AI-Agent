from pydantic import BaseModel

class LogEvent(BaseModel):
    source: str
    event_type: str
    message: str
    ip_address: str