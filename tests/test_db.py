
from app.models import database, models
from sqlalchemy import select


database.Base.metadata.create_all(bind=database.engine)

with database.SessionLocal() as session:
    new_inv = models.Investigation(name="abc", target="google.com")
    new_find = models.Finding(data="idk", module_source="idk", data_type="text", source="google.com")
    new_inv.inv.append(new_find)
    session.add(new_inv)
    session.commit()






