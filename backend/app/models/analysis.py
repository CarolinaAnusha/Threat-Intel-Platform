from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text

from app.models.database import Base


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)

    analysis_id = Column(String, unique=True)

    input_type = Column(String)

    content = Column(Text)

    risk_score = Column(Integer)

    risk_level = Column(String)

    created_at = Column(String)

    full_result = Column(Text)