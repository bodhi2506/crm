from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_migrate import Migrate
import logging
import traceback
import os
from config import Config
from models import db, User, Customer, Interaction, Order, Product, Activity

app = Flask(__name__)
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config.from_object(Config)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crm.db'

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Setup Logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper function to log activities
def log_activity(description):
    if current_user.is_authenticated:
        activity = Activity(Description=description, UserID=current_user.UserID)
        db.session.add(activity)
        db.session.commit()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            email = request.form['email']
            password = request.form['password']
            user = User.query.filter_by(Email=email).first()
            if user and bcrypt.check_password_hash(user.Password, password):
                login_user(user)
                session['logged_in'] = True
                session['user_id'] = user.UserID
                session['role'] = user.Role
                log_activity(f"{user.Role.capitalize()} logged in")
                flash('Login successful!', 'success')
                if user.Role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('customer_dashboard'))
            else:
                flash('Login Unsuccessful. Please check email and password', 'danger')
        except Exception as e:
            app.logger.error(f"Login error: {e}")
            traceback.print_exc()
            flash('An error occurred. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    try:
        log_activity(f"{current_user.Role.capitalize()} logged out")
        logout_user()
        session.clear()
        flash('You have been logged out.', 'success')
    except Exception as e:
        app.logger.error(f"Logout error: {e}")
        traceback.print_exc()
        flash('An error occurred during logout. Please try again.', 'danger')
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            email = request.form['email']
            password = request.form['password']
            role = request.form['role']
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(Email=email, Password=hashed_password, Role=role)
            db.session.add(new_user)
            db.session.commit()
            log_activity(f"New user registered: {email}")
            flash('Account created for {0}!'.format(email), 'success')
            return redirect(url_for('login'))
        except Exception as e:
            app.logger.error(f"Registration error: {e}")
            traceback.print_exc()
            flash('An error occurred. Please try again.', 'danger')
    return render_template('register.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))
    try:
        products = Product.query.all()
        customers = Customer.query.all()
        orders = Order.query.all()
        interactions = Interaction.query.all()
        activities = Activity.query.all()
    except Exception as e:
        app.logger.error(f"Admin dashboard error: {e}")
        traceback.print_exc()
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('home'))
    return render_template('admin_dashboard.html', products=products, customers=customers, orders=orders, interactions=interactions, activities=activities)

@app.route('/customer_dashboard')
@login_required
def customer_dashboard():
    if session['role'] != 'customer':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))
    try:
        products = Product.query.all()
        orders = Order.query.filter_by(CustomerID=current_user.CustomerID).all()
    except Exception as e:
        app.logger.error(f"Customer dashboard error: {e}")
        traceback.print_exc()
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('home'))
    return render_template('customer_dashboard.html', products=products, orders=orders)

@app.route('/purchase_product/<int:product_id>', methods=['POST'])
@login_required
def purchase_product(product_id):
    if session['role'] != 'customer':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))
    try:
        product = Product.query.get_or_404(product_id)
        order = Order(CustomerID=current_user.CustomerID, Status='Pending', TotalAmount=product.Price)
        db.session.add(order)
        db.session.commit()
        interaction = Interaction(CustomerID=current_user.CustomerID, InteractionType='Purchase', Notes=f"Purchased {product.ProductName}")
        db.session.add(interaction)
        db.session.commit()
        log_activity(f"Product purchased: {product.ProductName}")
        flash('Product purchased successfully!', 'success')
    except Exception as e:
        app.logger.error(f"Purchase product error: {e}")
        traceback.print_exc()
        flash('An error occurred. Please try again.', 'danger')
    return redirect(url_for('customer_dashboard'))

@app.route('/add_product', methods=['POST'])
@login_required
def add_product():
    if session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))
    try:
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        product = Product(ProductName=name, ProductDescription=description, Price=price)
        db.session.add(product)
        db.session.commit()
        log_activity(f"Product added: {name}")
        flash('Product added successfully!', 'success')
    except Exception as e:
        app.logger.error(f"Add product error: {e}")
        traceback.print_exc()
        flash('An error occurred. Please try again.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/edit_product/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_product(id):
    if session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))
    try:
        product = Product.query.get_or_404(id)
        if request.method == 'POST':
            product.ProductName = request.form['name']
            product.ProductDescription = request.form['description']
            product.Price = request.form['price']
            db.session.commit()
            log_activity(f"Product edited: {product.ProductName}")
            flash('Product updated successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        return render_template('edit_product.html', product=product)
    except Exception as e:
        app.logger.error(f"Edit product error: {e}")
        traceback.print_exc()
        flash('An error occurred. Please try again.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_product/<int:id>', methods=['POST'])
@login_required
def delete_product(id):
    if session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))
    try:
        product = Product.query.get_or_404(id)
        db.session.delete(product)
        db.session.commit()
        log_activity(f"Product deleted: {product.ProductName}")
        flash('Product deleted successfully!', 'success')
    except Exception as e:
        app.logger.error(f"Delete product error: {e}")
        traceback.print_exc()
        flash('An error occurred. Please try again.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/add_customer', methods=['POST'])
@login_required
def add_customer():
    if session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))
    try:
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        city = request.form['city']
        state = request.form['state']
        zip_code = request.form['zip']
        country = request.form['country']
        new_customer = Customer(FirstName=first_name, LastName=last_name, Email=email, PhoneNumber=phone, Address=address, City=city, State=state, ZipCode=zip_code, Country=country)
        db.session.add(new_customer)
        db.session.commit()
        log_activity(f"Customer added: {first_name} {last_name}")
        flash('Customer added successfully!', 'success')
    except Exception as e:
        app.logger.error(f"Add customer error: {e}")
        traceback.print_exc()
        flash('An error occurred. Please try again.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/edit_customer/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_customer(id):
    if session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))
    try:
        customer = Customer.query.get_or_404(id)
        if request.method == 'POST':
            customer.FirstName = request.form['first_name']
            customer.LastName = request.form['last_name']
            customer.Email = request.form['email']
            customer.PhoneNumber = request.form['phone']
            customer.Address = request.form['address']
            customer.City = request.form['city']
            customer.State = request.form['state']
            customer.ZipCode = request.form['zip']
            customer.Country = request.form['country']
            db.session.commit()
            log_activity(f"Customer edited: {customer.FirstName} {customer.LastName}")
            flash('Customer updated successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        return render_template('edit_customer.html', customer=customer)
    except Exception as e:
        app.logger.error(f"Edit customer error: {e}")
        traceback.print_exc()
        flash('An error occurred. Please try again.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_customer/<int:id>', methods=['POST'])
@login_required
def delete_customer(id):
    if session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))
    try:
        customer = Customer.query.get_or_404(id)
        db.session.delete(customer)
        db.session.commit()
        log_activity(f"Customer deleted: {customer.FirstName} {customer.LastName}")
        flash('Customer deleted successfully!', 'success')
    except Exception as e:
        app.logger.error(f"Delete customer error: {e}")
        traceback.print_exc()
        flash('An error occurred. Please try again.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/add_interaction', methods=['POST'])
@login_required
def add_interaction():
    if session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))
    try:
        customer_id = request.form['customer_id']
        interaction_type = request.form['interaction_type']
        notes = request.form['notes']
        new_interaction = Interaction(CustomerID=customer_id, InteractionType=interaction_type, Notes=notes)
        db.session.add(new_interaction)
        db.session.commit()
        log_activity(f"Interaction added for customer ID: {customer_id}")
        flash('Interaction added successfully!', 'success')
    except Exception as e:
        app.logger.error(f"Add interaction error: {e}")
        traceback.print_exc()
        flash('An error occurred. Please try again.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/edit_interaction/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_interaction(id):
    if session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))
    try:
        interaction = Interaction.query.get_or_404(id)
        if request.method == 'POST':
            interaction.InteractionType = request.form['interaction_type']
            interaction.Notes = request.form['notes']
            db.session.commit()
            log_activity(f"Interaction edited for customer ID: {interaction.CustomerID}")
            flash('Interaction updated successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        return render_template('edit_interaction.html', interaction=interaction)
    except Exception as e:
        app.logger.error(f"Edit interaction error: {e}")
        traceback.print_exc()
        flash('An error occurred. Please try again.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_interaction/<int:id>', methods=['POST'])
@login_required
def delete_interaction(id):
    if session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))
    try:
        interaction = Interaction.query.get_or_404(id)
        db.session.delete(interaction)
        db.session.commit()
        log_activity(f"Interaction deleted for customer ID: {interaction.CustomerID}")
        flash('Interaction deleted successfully!', 'success')
    except Exception as e:
        app.logger.error(f"Delete interaction error: {e}")
        traceback.print_exc()
        flash('An error occurred. Please try again.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/add_order', methods=['POST'])
@login_required
def add_order():
    if session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))
    try:
        customer_id = request.form['customer_id']
        status = request.form['status']
        total_amount = request.form['total_amount']
        new_order = Order(CustomerID=customer_id, Status=status, TotalAmount=total_amount)
        db.session.add(new_order)
        db.session.commit()
        log_activity(f"Order added for customer ID: {customer_id}")
        flash('Order added successfully!', 'success')
    except Exception as e:
        app.logger.error(f"Add order error: {e}")
        traceback.print_exc()
        flash('An error occurred. Please try again.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/edit_order/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_order(id):
    if session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))
    try:
        order = Order.query.get_or_404(id)
        if request.method == 'POST':
            order.Status = request.form['status']
            order.TotalAmount = request.form['total_amount']
            db.session.commit()
            log_activity(f"Order edited for customer ID: {order.CustomerID}")
            flash('Order updated successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        return render_template('edit_order.html', order=order)
    except Exception as e:
        app.logger.error(f"Edit order error: {e}")
        traceback.print_exc()
        flash('An error occurred. Please try again.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_order/<int:id>', methods=['POST'])
@login_required
def delete_order(id):
    if session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))
    try:
        order = Order.query.get_or_404(id)
        db.session.delete(order)
        db.session.commit()
        log_activity(f"Order deleted for customer ID: {order.CustomerID}")
        flash('Order deleted successfully!', 'success')
    except Exception as e:
        app.logger.error(f"Delete order error: {e}")
        traceback.print_exc()
        flash('An error occurred. Please try again.', 'danger')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
