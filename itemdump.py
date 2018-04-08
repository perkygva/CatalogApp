from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import datetime
from database_setup import *

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Clear catalog, items, and users for set-up
session.query(Category).delete()
session.query(Items).delete()
session.query(User).delete()

# Create fake users
User1 = User(name="F1",
              email="f20@gamil.com")
session.add(User1)
session.commit()

## User2 = User(name="F2",
##               email="f1@gmail.com")
## session.add(User2)
## session.commit()


# Create fake categories
Category1 = Category(name="Sports",
                     user_id=1)
session.add(Category1)
session.commit()

Category2 = Category(name="Cars",
                      user_id=2)
session.add(Category2)
session.commit

Category3 = Category(name="KidsToys",
                      user_id=1)
session.add(Category3)
session.commit()

Category4 = Category(name="Tech",
                      user_id=1)
session.add(Category4)
session.commit()

Category5 = Category(name="Literature",
                      user_id=1)
session.add(Category5)
session.commit()

# Populate a category with items for testing
# Using different users for items also
Item1 = Items(name="Snowboard",
               date=datetime.datetime.now(),
               description="Nidecker snowboard",
               price = "$499.00",
               category_id=1,
               user_id=1)
session.add(Item1)
session.commit()

Item2 = Items(name="Brazil Jersey",
               date=datetime.datetime.now(),
               description="Brazil team jersey - no 10 Neymar",
               price = "$99.00",
               category_id=1,
               user_id=1)
session.add(Item2)
session.commit()

Item3 = Items(name="Skateboard",
               date=datetime.datetime.now(),
               description="Tony Hawk original skateboard",
               price = "$199.00",
               category_id=1,
               user_id=1)
session.add(Item3)
session.commit()

Item4 = Items(name="Snowboard boots",
               date=datetime.datetime.now(),
               description="Nike snowboard boots size 12",
               price = "$199.00",
               category_id=1,
               user_id=1)
session.add(Item4)
session.commit()

Item5 = Items(name="Frozen dolls",
               date=datetime.datetime.now(),
               description="Collection of Disney Frozen dolls: 4 items",
               price = "$100.00",
               category_id=3,
               user_id=1)
session.add(Item5)
session.commit()

Item6 = Items(name="Moby Dick",
               date=datetime.datetime.now(),
               description="Signed original, classic novel",
               price = "$100.00",
               category_id=5,
               user_id=1)
session.add(Item6)
session.commit()

Item7 = Items(name="Treasure Island",
               date=datetime.datetime.now(),
               description="classic novel in mint condition",
               price = "$50.00",
               category_id=5,
               user_id=1)
session.add(Item7)
session.commit()

print "Your database has been populated for testing!"
