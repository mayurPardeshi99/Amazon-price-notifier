from flask import Flask, render_template, url_for, request, redirect, flash, get_flashed_messages, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Mail, Message
from datetime import date
from fetch_price import Fetch_Price
from functools import wraps
from dotenv import load_dotenv
import os

load_dotenv()

# ENV variables
API_KEY = os.getenv("API_KEY")
ADMIN = os.getenv("EMAIL")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Set up flask_login module
login_manager = LoginManager()
login_manager.init_app(app)

# Flask mail configuration
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("EMAIL")
app.config["MAIL_PASSWORD"] = os.getenv("PASSWORD")

mail = Mail(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(200))
    last_name = db.Column(db.String(200))
    email = db.Column(db.String(200), unique=True)
    password = db.Column(db.String(100))
    # User's added product
    added_products = relationship("Product", back_populates="user")
    checked_products = relationship("Price_Dropped_Product", back_populates="user")

    # Create token
    def get_token(self, expires_sec=900):
        serial = Serializer(app.config['SECRET_KEY'], expires_in=expires_sec)
        return serial.dumps({"user_id": self.id}).decode("utf-8")

    # Verify token
    @staticmethod
    def verify_token(token):
        serial = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = serial.loads(token)["user_id"]
        except:
            return None
        return User.query.get(user_id)


class Product(db.Model):
    __tablename__ = "products"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    add_date = db.Column(db.String(250), nullable=False)
    product_name = db.Column(db.Text, nullable=False)
    product_url = db.Column(db.Text, nullable=False)
    current_price = db.Column(db.String(300), nullable=False)
    budget = db.Column(db.String(300), nullable=False)
    user = relationship("User", back_populates="added_products")

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}


class Price_Dropped_Product(db.Model):
    __tablename__ = "price_dropped_products"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    price_dropped_date = db.Column(db.String(250), nullable=False)
    product_name = db.Column(db.Text, nullable=False)
    product_url = db.Column(db.Text, nullable=False)
    dropped_price = db.Column(db.String(300), nullable=False)
    budget = db.Column(db.String(300), nullable=False)
    user = relationship("User", back_populates="checked_products")


class Our_Product(db.Model):
    __tablename__ = "our_products"
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.Text, nullable=False)
    product_url = db.Column(db.Text, nullable=False)
    product_img = db.Column(db.Text, nullable=False)


# db.create_all()

# Admin only page decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.email == ADMIN:
            return f(*args, **kwargs)
        return abort(403)

    return decorated_function


# User only page decorator
def user_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.email != ADMIN and current_user.is_authenticated:
            return f(*args, **kwargs)
        elif current_user.email == ADMIN and current_user.is_authenticated:
            return redirect(url_for("admin_dashboard"))
        return abort(403)

    return decorated_function


def send_token(user):
    token = user.get_token()
    msg = Message("Password reset request", recipients=[user.email], sender=ADMIN)
    msg.body = f"To reset your password, please follow the link below.\n" \
               f"Link is only valid for 15 minutes\n" \
               f"{url_for('set_password', token=token, _external=True)}\n" \
               f"If you didn't send a password reset request, please ignore this message."

    mail.send(msg)


@app.route("/")
def home():
    return render_template("index.html", current_user=current_user, admin=ADMIN)


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for("user_dashboard"))
    else:
        if request.method == "POST":
            email = request.form.get("email")
            password = request.form.get("password")
            user = User.query.filter_by(email=email).first()
            if user:
                if check_password_hash(user.password, password):
                    login_user(user)
                    return redirect(url_for("user_dashboard"))
                else:
                    flash("The password doesn't match, please try again.")
            else:
                flash("The email does not exist, Please try again.")
            return redirect(url_for("login_page"))
        return render_template("login.html", current_user=current_user, admin=ADMIN)


@app.route("/sign-up", methods=["GET", "POST"])
def sign_up_page():
    if current_user.is_authenticated:
        return redirect(url_for("user_dashboard"))
    else:
        if request.method == "POST":
            fname = request.form.get("fname")
            lname = request.form.get("lname")
            email = request.form.get("email")
            password = request.form.get("password")
            confirm_password = request.form.get("confirm_password")
            if password == confirm_password:
                if User.query.filter_by(email=email).first():
                    flash("You've already signed up with that email, log in instead!")
                    return redirect(url_for('sign_up_page'))
                else:
                    hashed_password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
                    new_user = User(
                        first_name=fname.title(),
                        last_name=lname.title(),
                        email=email,
                        password=hashed_password
                    )
                    db.session.add(new_user)
                    db.session.commit()
                    login_user(new_user)
                return redirect(url_for("user_dashboard"))
            else:
                flash("Password and confirm password should be same.")
                return redirect(url_for("sign_up_page"))
        return render_template("register.html", current_user=current_user, admin=ADMIN)


# Enter email for forgot password
@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for("user_dashboard"))
    else:
        if request.method == "POST":
            email = request.form.get("email")
            user = User.query.filter_by(email=email).first()
            if user:
                send_token(user)
                flash("Reset request sent, please check your email.", "success")
                return redirect(url_for("login_page"))
            else:
                flash("The email does not exist, Please try again.")
                return redirect(url_for("reset_password"))
    return render_template("reset-password.html", current_user=current_user, admin=ADMIN)


# Set password for forget password and set password before login
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def set_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("user_dashboard"))
    else:
        user = User.verify_token(token)
        if user is None:
            flash("This token is invalid or expired, please try again.")
            return redirect(url_for("reset_password"))
        else:
            if request.method == "POST":
                password = request.form.get("password")
                confirm_password = request.form.get("confirm_password")
                if password == confirm_password:
                    hashed_password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
                    user.password = hashed_password
                    db.session.commit()
                    flash("Password changed successfully, please login.", "success")
                    return redirect(url_for("login_page"))
                else:
                    flash("Password and confirm password should be same.")
                    return redirect(url_for("set_password", token=token))
            return render_template("set-password.html", current_user=current_user, token=token, admin=ADMIN)


@app.route("/user")
@login_required
@user_only
def user_dashboard():
    return render_template("tables.html", current_user=current_user, admin=ADMIN)


@app.route("/user/history")
@login_required
@user_only
def user_history():
    return render_template("history.html", current_user=current_user, admin=ADMIN)


@app.route("/user/add", methods=["GET", "POST"])
@login_required
@user_only
def add_url():
    if request.method == "POST":
        url = request.form.get("url")
        unformatted_budget = request.form.get("budget")
        budget = unformatted_budget.replace(",", "")
        if url != "":
            fetch = Fetch_Price(url=url)
            product_data = fetch.get_data()
            if product_data is not False:
                price = product_data["price"]
                if price != "NA":
                    formatted_price = float(price.replace(",", ""))
                    # If product current price is in user's budget
                    if float(budget) >= formatted_price:
                        new_checked_product = Price_Dropped_Product(
                            user=current_user,
                            price_dropped_date=date.today().strftime("%d/%m/%Y"),
                            product_name=product_data["name"],
                            product_url=product_data["url"],
                            dropped_price=price,
                            budget=unformatted_budget
                        )
                        db.session.add(new_checked_product)
                        db.session.commit()
                        return redirect(url_for("user_history"))
                    else:
                        # If product current price is not in user's budget
                        new_product = Product(
                            user=current_user,
                            add_date=date.today().strftime("%d/%m/%Y"),
                            product_name=product_data["name"],
                            product_url=product_data["url"],
                            current_price=price,
                            budget=unformatted_budget
                        )
                        db.session.add(new_product)
                        db.session.commit()
                        return redirect(url_for("user_dashboard"))
                flash("Product is not available, please wait until it gets available")
            else:
                flash("Invalid URL, please enter correct url.")
            return redirect(url_for("add_url"))
    return render_template("add.html", current_user=current_user, admin=ADMIN)


@app.route("/user/product/delete/<int:product_id>")
@login_required
@user_only
def delete_product(product_id):
    product_to_delete = Product.query.get(product_id)
    if product_to_delete:
        if current_user.id == product_to_delete.user.id:
            db.session.delete(product_to_delete)
            db.session.commit()
    return redirect(url_for("user_dashboard"))


@app.route("/user/dropped-product/delete/<int:product_id>")
@login_required
@user_only
def delete_price_dropped_product(product_id):
    product_to_delete = Price_Dropped_Product.query.get(product_id)
    if product_to_delete:
        if current_user.id == product_to_delete.user.id:
            db.session.delete(product_to_delete)
            db.session.commit()
    return redirect(url_for("user_history"))


@app.route("/user/settings")
@login_required
def settings():
    return render_template("settings.html", current_user=current_user, admin=ADMIN)


@app.route("/settings/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        if current_user.is_authenticated:
            if new_password == confirm_password:
                if check_password_hash(current_user.password, old_password):
                    user_to_update = User.query.get(current_user.id)
                    user_to_update.password = generate_password_hash(new_password, method="pbkdf2:sha256",
                                                                     salt_length=8)
                    db.session.commit()
                    flash("Successfully updated the password.")
                    return redirect(url_for("settings"))
                else:
                    flash("The old password is incorrect, please try again.")
            else:
                flash("Password and confirm password should be same.")
            return redirect(url_for("change_password"))
    return render_template("change-password.html", current_user=current_user, admin=ADMIN)


@app.route("/user/settings/change-email", methods=["GET", "POST"])
@login_required
@user_only
def change_email():
    if request.method == "POST":
        new_email = request.form.get("new_email")
        password = request.form.get("password")
        if current_user.is_authenticated:
            if User.query.filter_by(email=new_email).first():
                flash("The email already exist, please enter valid email id.")
                return redirect(url_for("change_email"))
            else:
                if check_password_hash(current_user.password, password):
                    user_to_update = User.query.get(current_user.id)
                    user_to_update.email = new_email
                    db.session.commit()
                    flash("Successfully updated the email id.")
                    return redirect(url_for("settings"))
                else:
                    flash("The password doesn't match, please try again.")
                    return redirect(url_for("change_email"))
    return render_template("change-email.html", current_user=current_user, admin=ADMIN)


@app.route("/log-out")
@login_required
def log_out():
    logout_user()
    return redirect(url_for("home"))


# Admin
@app.route("/admin")
@login_required
@admin_only
def admin_dashboard():
    all_price_dropped_products = Price_Dropped_Product.query.count()
    all_added_products = Product.query.count()
    today_price_dropped_product = Price_Dropped_Product.query.filter_by(price_dropped_date=date.today()
                                                                        .strftime("%d/%m/%Y")).count()
    today_added_products = Product.query.filter_by(add_date=date.today().strftime("%d/%m/%Y")).count()
    products_details = {
        "all_price_dropped_products": all_price_dropped_products,
        "all_added_products": all_added_products,
        "today_price_dropped_product": today_price_dropped_product,
        "today_added_products": today_added_products
    }
    users = User.query.all()
    return render_template("admin.html", current_user=current_user, products_details=products_details, users=users,
                           admin=ADMIN)


@app.route("/our-products")
@login_required
def our_products():
    all_products = Our_Product.query.all()
    return render_template("products.html", all_products=all_products, current_user=current_user, admin=ADMIN)


@app.route("/admin/add-product", methods=["GET", "POST"])
@login_required
@admin_only
def admin_add_product():
    if request.method == "POST":
        url = request.form.get("url")
        if url != "":
            fetch = Fetch_Price(url=url)
            product_data = fetch.get_data()
            if product_data is not False:
                our_new_product = Our_Product(
                    product_name=product_data["name"],
                    product_url=product_data["url"],
                    product_img=product_data["img_src"]
                )
                db.session.add(our_new_product)
                db.session.commit()
                return redirect(url_for("our_products"))
            else:
                flash("Invalid URL, please enter correct url.")
                return redirect(url_for("admin_add_product"))
    return render_template("add-my-product.html", current_user=current_user, admin=ADMIN)


# API for getting prices to check everyday
@app.route("/get-products-details/all")
def get_all_products():
    api_key = request.headers.get("api_key")
    if api_key == API_KEY:
        if request.args:
            return jsonify(error={
                "error": "Sorry, link is incorrect."
            }), 403
        else:
            products = Product.query.all()
            return jsonify(table=[product.to_dict() for product in products])
    else:
        return jsonify(error={
            "error": "Sorry, that's not allowed."
        }), 403


@app.route("/update-products-price/<int:product_id>", methods=["PATCH"])
def update_price(product_id):
    api_key = request.headers.get("api_key")
    if api_key == API_KEY:
        product = Product.query.get(product_id)
        if product:
            new_price = request.args.get("new_price")
            if new_price:
                product.current_price = new_price
                db.session.commit()
                return jsonify(success="Successfully updated the current price.")
            else:
                return jsonify(error={
                    "error": "Sorry, that's not allowed."
                }), 403
        else:
            return jsonify(error={
                "Not-found": "Sorry a product with that id was not found in the database."
            }), 404
    else:
        return jsonify(error={
            "error": "Sorry, that's not allowed."
        }), 403


@app.route("/get-user/name-email/<int:user_id>")
def get_user_data(user_id):
    api_key = request.headers.get("api_key")
    if api_key == API_KEY:
        if request.args:
            return jsonify(error={
                "error": "Sorry, link is incorrect."
            }), 403
        else:
            user = User.query.get(user_id)
            if user:
                return jsonify(user={
                    "name": f"{user.first_name} {user.last_name}",
                    "email": user.email
                })
            else:
                return jsonify(error={
                    "Not-found": "Sorry a user with that id was not found in the database."
                }), 404
    else:
        return jsonify(error={
            "error": "Sorry, that's not allowed."
        }), 403


@app.route("/add-price-dropped-product/<int:product_id>", methods=["DELETE"])
def add_price_dropped_product(product_id):
    api_key = request.headers.get("api_key")
    if api_key == API_KEY:
        product = Product.query.get(product_id)
        if product:
            dropped_price = request.args.get("dropped_price")
            if dropped_price:
                new_price_dropped_product = Price_Dropped_Product(
                    user_id=product.user_id,
                    price_dropped_date=date.today().strftime("%d/%m/%Y"),
                    product_name=product.product_name,
                    product_url=product.product_url,
                    dropped_price=dropped_price,
                    budget=product.budget
                )
                db.session.add(new_price_dropped_product)
                db.session.commit()
                db.session.delete(product)
                db.session.commit()
                return jsonify(success="Successfully updated price dropped product.")
            else:
                return jsonify(error={
                    "error": "Sorry, that's not allowed."
                }), 403
        else:
            return jsonify(error={
                "Not-found": "Sorry a product with that id was not found in the database."
            }), 404
    else:
        return jsonify(error={
            "error": "Sorry, that's not allowed."
        }), 403


if __name__ == "__main__":
    app.run(debug=True)
