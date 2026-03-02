"""
This script runs the application using a development server.
It contains the definition of routes and views for the application.
"""
import os
import csv
import datetime
from OpenSSL import crypto
import sqlite3
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
# simple secret for flashing; override via environment in production
app.secret_key = "os-prep-secret-key"

# Make the WSGI interface available at the top level so wfastcgi can get it.
wsgi_app = app.wsgi_app

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
def check_password(password, stored_hash):
    return hash_password(password) == stored_hash

DB_NAME = "site.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn
def init_db():
    conn = get_db_connection()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
""")
    conn.commit()
    conn.close()

def generate_self_signed_cert(cert_file='ssl_cert.pem', key_file='ssl_key.pem'):
    # Create a key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Create a self-signed certificate
    cert = crypto.X509()
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(315360000)  # 10 years
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')
    # Save the private key and certificate to files
    with open(key_file, 'wb') as key_file_out:
        key_file_out.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    with open(cert_file, 'wb') as cert_file_out:
        cert_file_out.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    print(f"Self-signed certificate generated: {cert_file}")
    print(f"Private key generated: {key_file}")

# Call the function to generate the cert and key




@app.route('/')
def home():
    return render_template('home.html')

@app.route('/products')
def products():
    return render_template('products.html')

@app.route('/books')
def books():
    return render_template('books.html')

@app.route('/ener')
def ener():
    return render_template('EC.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 1. Validation check
        if not username or not password:
            flash("All fields are required.")
            return redirect(url_for("register"))

        password_hash = hash_password(password)

        try:
            # 2. Secure database interaction
            with get_db_connection() as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash)
                )
                conn.commit()
        except sqlite3.IntegrityError:
            flash("Username already exists. Choose another.")
            return redirect(url_for("register"))
        except Exception as e:
            flash(f"An unexpected error occurred: {e}")
            return redirect(url_for("register"))

        flash("Account created! Please log in.")
        return redirect(url_for("login"))

    # 3. GET request handler
    return render_template("register.html")

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        email = (request.form.get('email') or '').strip()
        message = (request.form.get('message') or '').strip()

        # basic validation
        if not name or not email or not message:
            flash('Please fill in all fields.', 'danger')
            return render_template('contact.html', form=request.form)

        if '@' not in email or len(email) < 5:
            flash('Please enter a valid email address.', 'danger')
            return render_template('contact.html', form=request.form)

        # persist message (append to CSV) using UTF-8 encoding
        try:
            os.makedirs('data', exist_ok=True)
            with open(os.path.join('data', 'contacts.csv'), 'a', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([datetime.datetime.utcnow().isoformat(), name, email, message])
        except Exception as ex:
            # log the error server-side and inform the user
            print('Failed to save contact message:', ex)
            flash('An internal error occurred. Please try again later.', 'danger')
            return render_template('contact.html', form=request.form)

        flash('Thanks — your message was received.', 'success')
        return redirect(url_for('contact'))

    return render_template('contact.html')

@app.route('/crying')
def nawa():
    return render_template('bookog.html')

@app.route('/gpt')
def ouch():
    return render_template('bookgt.html')


if __name__ == '__main__':
    init_db()
    generate_self_signed_cert()
    HOST = os.environ.get('SERVER_HOST', 'localhost')
    try:
        PORT = int(os.environ.get('SERVER_PORT', '5555'))
    except ValueError:
        PORT = 5555
    app.run(HOST, PORT, ssl_context=('ssl_cert.pem', 'ssl_key.pem'))