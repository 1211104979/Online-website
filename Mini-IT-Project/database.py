
from app import db, Class


Class1 = Class(name="Genshin Impact", 
                    price=59, 
                    description="work in progress")
Class2 = Class(name="Tower Of Fantasy", 
                    price=549, 
                    description="work in progress")
Class3 = Class(name="Valorant", 
                    price=69, 
                    description="work in progress")
Class4 = Class(name="Apex Legend", 
                    price=69, 
                    description="work in progress")
db.session.add(Class1)
db.session.add(Class2)
db.session.add(Class3)
db.session.add(Class4)
db.session.commit()



