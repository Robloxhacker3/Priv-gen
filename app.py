from flask import Flask, request, jsonify, send_file, render_template
import os
import zipfile
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import secrets

app = Flask(__name__)

# Function to generate a private .p12 certificate
def generate_private_certificate(folder_path, password):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    p12_path = os.path.join(folder_path, "private.p12")
    with open(p12_path, "wb") as p12_file:
        p12_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            )
        )
    return p12_path

# Function to create a .mobileprovision file
def generate_mobile_provision(folder_path):
    provision_path = os.path.join(folder_path, "private.mobileprovision")
    with open(provision_path, "w") as provision_file:
        provision_file.write("This is a placeholder for a .mobileprovision file.")
    return provision_path

# Function to create a text file with the password
def create_password_file(folder_path, password):
    password_file_path = os.path.join(folder_path, "password.txt")
    with open(password_file_path, "w") as password_file:
        password_file.write(f"Your password is: {password}")
    return password_file_path

# Main function to generate the zip file
def create_certificate_zip(output_zip_path):
    password = secrets.token_hex(16)
    folder_name = "Private_Certificate"
    os.makedirs(folder_name, exist_ok=True)

    try:
        generate_private_certificate(folder_name, password)
        generate_mobile_provision(folder_name)
        create_password_file(folder_name, password)

        with zipfile.ZipFile(output_zip_path, "w") as zipf:
            for root, _, files in os.walk(folder_name):
                for file in files:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.relpath(file_path, folder_name))
    finally:
        for root, _, files in os.walk(folder_name, topdown=False):
            for file in files:
                os.remove(os.path.join(root, file))
            os.rmdir(root)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate():
    data = request.json
    udid = data.get('udid')
    discord_username = data.get('discordUsername')

    if not udid or not discord_username:
        return jsonify({"error": "Missing fields"}), 400

    zip_file_path = "private_certificate.zip"
    create_certificate_zip(zip_file_path)
    return send_file(zip_file_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
