from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'Users'
    UserID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Email = db.Column(db.String(100), unique=True, nullable=False)
    Password = db.Column(db.String(200), nullable=False)
    Role = db.Column(db.String(50), nullable=False)
    Name = db.Column(db.String(120))
    CustomerID = db.Column(db.Integer, db.ForeignKey('Customers.CustomerID', name='fk_user_customer'))
    Created_At = db.Column(db.DateTime, default=db.func.current_timestamp())

    def get_id(self):
        return str(self.UserID)

class Customer(db.Model):
    __tablename__ = 'Customers'
    CustomerID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    FirstName = db.Column(db.String(50), nullable=False)
    LastName = db.Column(db.String(50), nullable=False)
    Email = db.Column(db.String(100), unique=True, nullable=False)
    PhoneNumber = db.Column(db.String(15))
    Address = db.Column(db.String(255))
    City = db.Column(db.String(50))
    State = db.Column(db.String(50))
    ZipCode = db.Column(db.String(10))
    Country = db.Column(db.String(50))

class Interaction(db.Model):
    __tablename__ = 'Interactions'
    InteractionID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    CustomerID = db.Column(db.Integer, db.ForeignKey('Customers.CustomerID', name='fk_interaction_customer'), nullable=False)
    InteractionDate = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)
    InteractionType = db.Column(db.String(50), nullable=False)
    Notes = db.Column(db.Text)

class Order(db.Model):
    __tablename__ = 'Orders'
    OrderID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    CustomerID = db.Column(db.Integer, db.ForeignKey('Customers.CustomerID', name='fk_order_customer'), nullable=False)
    OrderDate = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)
    Status = db.Column(db.String(50), nullable=False)
    TotalAmount = db.Column(db.Float, nullable=False)

class Product(db.Model):
    __tablename__ = 'Products'
    ProductID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ProductName = db.Column(db.String(100), nullable=False)
    ProductDescription = db.Column(db.Text, nullable=False)
    Price = db.Column(db.Float, nullable=False)

class Activity(db.Model):
    __tablename__ = 'Activities'
    ActivityID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Description = db.Column(db.String(255), nullable=False)
    Date = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)
    UserID = db.Column(db.Integer, db.ForeignKey('Users.UserID', name='fk_activity_user'), nullable=False)
    User = db.relationship('User', backref=db.backref('activities', lazy=True))
