from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os

app = Flask(__name__)

# Generate a secret key
secret_key = os.urandom(16)

# Define encryption and decryption functions
def encrypt(plaintext):
    cipher = AES.new(secret_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ciphertext).decode('utf-8')
    return iv + ':' + ct

def decrypt(ciphertext):
    iv, ct = ciphertext.split(':')
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(secret_key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ct), AES.block_size)
    return plaintext.decode('utf-8')

# Define routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/encrypt', methods=['GET','POST'])
def encrypt_page():
    if request.method == 'POST':
        plaintext = request.form['plaintext']
        ciphertext = encrypt(plaintext)
        return render_template('encrypt.html', ciphertext=ciphertext)
    else:
        return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET','POST'])
def decrypt_page():
    if request.method == 'POST':
        ciphertext = request.form['ciphertext']
        plaintext = decrypt(ciphertext)
        return render_template('decrypt.html', plaintext=plaintext)
    else:
        return render_template('decrypt.html')

if __name__ == '__main__':
    app.run(debug=True)
