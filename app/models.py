from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.types import JSON
from datetime import datetime
from .db import Base

# Store tags as comma-separated string for simplicity.
# Store recurrence_params as JSON text to support flexible schemas.

class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    type = Column(String(100), nullable=True)
    subtype = Column(String(100), nullable=True)
    url = Column(String(1000), nullable=True)
    description = Column(Text, nullable=True)
    tags = Column(String(1000), nullable=True)  # "tag1,tag2"
    recurrence_mode = Column(String(16), nullable=False)  # none | after | cron | set
    recurrence_params = Column(Text, nullable=True)       # JSON as text
    due_at = Column(DateTime, nullable=True)              # used when mode == none
    last_completed_at = Column(DateTime, nullable=True)
    next_due_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)
