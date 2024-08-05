from sqlalchemy import create_engine

DATABASE_URI = 'sqlite:///crm.db'
engine = create_engine(DATABASE_URI)

try:
    with engine.connect() as connection:
        print("Connection to the database was successful.")
except Exception as e:
    print(f"An error occurred: {e}")