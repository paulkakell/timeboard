from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.sql import func
from .db import Base

class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    type = Column(String(100), nullable=True)
    subtype = Column(String(100), nullable=True)
    url = Column(String(1000), nullable=True)
    description = Column(Text, nullable=True)
    tags = Column(String(1000), nullable=True)  # comma separated
    recurrence_mode = Column(String(16), nullable=False)  # none | after | cron | set
    recurrence_params = Column(Text, nullable=True)       # JSON string
    due_at = Column(DateTime(timezone=True), nullable=True)
    next_due_at = Column(DateTime(timezone=True), nullable=True)
    last_done_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
