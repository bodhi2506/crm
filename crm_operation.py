from app import app, db
from models import Customer

def create_customer(customer_data):
    new_customer = Customer(
        first_name=customer_data['first_name'],
        last_name=customer_data['last_name'],
        email=customer_data['email'],
        phone_number=customer_data['phone_number'],
        address=customer_data['address'],
        city=customer_data['city'],
        state=customer_data['state'],
        zip_code=customer_data['zip_code'],
        country=customer_data['country']
    )
    db.session.add(new_customer)
    db.session.commit()
    return new_customer.id

def update_customer(customer_id, updated_data):
    customer = Customer.query.get(customer_id)
    if customer:
        customer.first_name = updated_data['first_name']
        customer.last_name = updated_data['last_name']
        customer.email = updated_data['email']
        customer.phone_number = updated_data['phone_number']
        customer.address = updated_data['address']
        customer.city = updated_data['city']
        customer.state = updated_data['state']
        customer.zip_code = updated_data['zip_code']
        customer.country = updated_data['country']
        db.session.commit()

def delete_customer(customer_id):
    customer = Customer.query.get(customer_id)
    if customer:
        db.session.delete(customer)
        db.session.commit()

def select_all_customers():
    return Customer.query.all()

if __name__ == '__main__':
    with app.app_context():
        # Example Usage
        customer_data = {
            'first_name': 'Alice',
            'last_name': 'Johnson',
            'email': 'alice.johnson@example.com',
            'phone_number': '555-123-4567',
            'address': '789 Pine St',
            'city': 'Sometown',
            'state': 'Somestate',
            'zip_code': '54321',
            'country': 'USA'
        }
        # Insert a customer
        new_customer_id = create_customer(customer_data)
        
        # Update a customer
        updated_customer_data = {
            'first_name': 'Alice',
            'last_name': 'Johnson',
            'email': 'alice.johnson@example.com',
            'phone_number': '555-123-4567',
            'address': '789 Pine St',
            'city': 'Sometown',
            'state': 'Somestate',
            'zip_code': '54321',
            'country': 'USA'
        }
        update_customer(new_customer_id, updated_customer_data)

        # Delete a customer
        # delete_customer(new_customer_id)

        # Select all customers
        all_customers = select_all_customers()
        for customer in all_customers:
            print(customer)
