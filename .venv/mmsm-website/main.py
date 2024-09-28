import json
from flask import Flask, render_template, redirect, flash, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = "TheGreastesttimeTravlingDeviceisTimeSTONE"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///user.db"

# Initialize extensions
csrf = CSRFProtect(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


doc_folder_path = os.path.join(app.root_path, 'static', 'confidential_doc')


# with app.app_context():
#     db.drop_all()
#     db.create_all()
#
# with app.app_context():
#     password = generate_password_hash("Testing101", method='pbkdf2:sha256', salt_length=8)
#     new_user = User(name="Admin", password=password)
#     db.session.add(new_user)
#     db.session.commit()
#
#     print("User created successfully.")

# Form for login
class MyForm(FlaskForm):
    name = StringField('Username', validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


# Create tables
with app.app_context():
    db.create_all()


# Routes
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/work")
def work():
    photo_folder = os.path.join(app.static_folder, 'assets', 'photos')

    # Get the sorted list of photos
    photos = sorted([f for f in os.listdir(photo_folder) if f.startswith('photo-') and f.endswith('.jpg')])

    # Define labels corresponding to each photo
    labels = [
        "Meeting with Nagpur Education Officer",  # Corresponding to photos[0]
        "Member's Birthday Celebration",  # Corresponding to photos[1]
        "Meeting with Former Education Officer",
        "Meeting with Former Education Officer",
        "Protest against OPS",
        "Presenting our case to the Education Officer on behalf of the teachers' committee",
        "Committee Protesting against wrong being",
    ]

    photos_per_row = 2

    return render_template("work.html", photos=photos, labels=labels, photos_per_row=photos_per_row)


@app.route("/about")
def about():
    photos_dir = os.path.join(app.static_folder, 'assets', 'individual-photos')
    descriptions_file = os.path.join(app.static_folder, 'assets', 'details.json')

    # Load descriptions from the JSON file
    descriptions = {}
    try:
        with open(descriptions_file, encoding='utf-8') as f:
            descriptions = json.load(f)
    except FileNotFoundError:
        print(f"File not found: {descriptions_file}")
    except json.JSONDecodeError:
        print(f"Error decoding JSON file: {descriptions_file}")
    except UnicodeDecodeError as e:
        print(f"Unicode decode error: {e}")

    # List to hold member data
    members = []

    # Define files you want to exclude (1.jpg to 5.jpg)
    exclude_files = {'1.jpg', '2.jpg', '3.jpg', '4.jpg', '5.jpg'}

    # Sort the photos_list based on the order of keys in the descriptions JSON
    photos_list = sorted(
        [f for f in os.listdir(photos_dir) if f.endswith(('.jpg', '.jpeg', '.png')) and f not in exclude_files],
        key=lambda x: list(descriptions.keys()).index(x) if x in descriptions else float('inf')
    )

    # Start adding members from the specified start photo ('6.jpg')
    add = False
    start_photo = '6.jpg'

    for photo_filename in photos_list:
        if photo_filename == start_photo:
            add = True
        if add:
            # Append the member's photo and details based on the description
            member = {
                'photo': photo_filename,
                'name': descriptions.get(photo_filename, {}).get('name', f'Member Name {len(members) + 1}'),
                'details': descriptions.get(photo_filename, {}).get('details', 'Placeholder details'),
                'description': descriptions.get(photo_filename, {}).get('description', 'Placeholder description')
            }
            members.append(member)

    print("Photos in directory:", photos_list)
    print("JSON order:", list(descriptions.keys()))
    print("Members being added:")
    return render_template('about.html', members=members)


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = MyForm()
    if form.validate_on_submit():
        username = form.name.data
        password = form.password.data

        # Debugging: print submitted data
        # print(f"Submitted Username: {username}")
        # print(f"Submitted Password: {password}")
        # Query the user from the database
        user = User.query.filter_by(name=username).first()

        if user:
            # print("User found in database.")
            # print(f"Stored Hash: {user.password}")
            if check_password_hash(user.password, password):
                # print("Password matched.")
                login_user(user)
                flash('Logged in successfully.')
                return redirect(url_for('protected'))
            else:
                pass
                # print("Password did not match.")
        else:
            pass
            # print("User not found in database.")

        flash('Invalid username or password')

    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('home'))


def get_doc_names():
    files = os.listdir(doc_folder_path)

    docs = [f for f in files if os.path.isfile(os.path.join(doc_folder_path, f))]

    return docs


@app.route('/protected')
@login_required
def protected():
    doc_names = get_doc_names()
    return render_template("protected_docs.html", name=doc_names)


@app.route("/downloads/<filename>")
@login_required
def downloads(filename):
    directory = "static/confidential_doc"
    filename = filename
    return send_from_directory(directory, filename, as_attachment=True)


def get_local_doc_names():
    local_doc_folder = os.path.join(app.static_folder, 'local_doc')
    return [f for f in os.listdir(local_doc_folder) if os.path.isfile(os.path.join(local_doc_folder, f))]


@app.route("/government_relations")
def gr_doc():
    local_doc_names = get_local_doc_names()
    return render_template("local_docs.html", names=local_doc_names)


@app.route("/local_downloads/<name>")
def local_downloads(name):
    directory = "static/local_doc"
    filename = name
    return send_from_directory(directory, filename, as_attachment=True)



if __name__ == "__main__":
    app.run(debug=True)