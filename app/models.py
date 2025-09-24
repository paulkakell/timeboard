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
<<<<<<< HEAD
    recurrence_params = Column(Text, nullable=True)       # JSON in string
    due_at = Column(DateTime, nullable=True)              # when mode == none
    last_completed_at = Column(DateTime, nullable=True)
    next_due_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)


from sqlalchemy import Column, String

class MetaKV(Base):
    __tablename__ = "meta"
    key = Column(String(100), primary_key=True)
    value = Column(String(2000), nullable=True)
=======
    recurrence_params = Column(Text, nullable=True)       # JSON string
    due_at = Column(DateTime(timezone=True), nullable=True)
    next_due_at = Column(DateTime(timezone=True), nullable=True)
    last_done_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
>>>>>>> c12f6754ab679429516c92e84fa106cf949a473f
