from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import joblib
from flask import Flask, render_template, request, jsonify
from flask import Flask, render_template, request, jsonify
import model
import torch
from torch import nn as nn
from torch.nn import functional as F
import pandas as pd
from tqdm import tqdm

from joblib import Parallel, delayed
import joblib
import numpy as np  # linear algebra
import pandas as pd  # data processing, CSV file I/O (e.g. pd.read_csv)
import seaborn as sns
import matplotlib.pyplot as plt
from keras.models import load_model
import re
from tld import get_tld
from typing import Tuple, Union, Any
from sklearn.preprocessing import MinMaxScaler
from colorama import Fore  # Colorama is a module to color the python outputs

from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

USERS_FILE = 'users.json'

# Ensure the users.json file exists
def ensure_users_file():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w') as f:
            json.dump({}, f)

# Load user data from file
def load_users():
    ensure_users_file()
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

# Save user data to file
def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        users = load_users()
        if username in users:
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        users[username] = hashed_password
        save_users(users)

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        users = load_users()
        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('process'))

        flash('Invalid username or password!', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/process', methods=['GET', 'POST'])
def process():
    if request.method == 'POST':
        # Retrieve input from form
        data = request.form['name']
        data = {"url": [data]}
        data = pd.DataFrame(data)

        # Feature extraction
        data['url_len'] = data['url'].apply(lambda x: len(str(x)))

        def process_tld(url):
            try:
                res = get_tld(url, as_object=True, fail_silently=False, fix_protocol=True)
                pri_domain = res.parsed_url.netloc
            except:
                pri_domain = None
            return pri_domain

        data['domain'] = data['url'].apply(lambda i: process_tld(i))
        feature = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']
        for a in feature:
            data[a] = data['url'].apply(lambda i: i.count(a))

        def abnormal_url(url):
            hostname = urlparse(url).hostname
            hostname = str(hostname)
            match = re.search(hostname, url)
            return 1 if match else 0

        data['abnormal_url'] = data['url'].apply(lambda i: abnormal_url(i))

        def http_secure(url):
            htp = urlparse(url).scheme
            return 1 if htp == 'https' else 0

        data['https'] = data['url'].apply(lambda i: http_secure(i))

        def digit_count(url):
            return sum(1 for i in url if i.isnumeric())

        data['digits'] = data['url'].apply(lambda i: digit_count(i))

        def letter_count(url):
            return sum(1 for i in url if i.isalpha())

        data['letters'] = data['url'].apply(lambda i: letter_count(i))

        def shortining_service(url):
            match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                              'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                              'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                              'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                              'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                              'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                              'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                              'tr\.im|link\.zip\.net',
                              url)
            return 1 if match else 0

        data['Shortining_Service'] = data['url'].apply(lambda x: shortining_service(x))

        def having_ip_address(url):
            match = re.search(
                '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
                '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'
                '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
                '([0-9]+(?:\\.[0-9]+){3}:[0-9]+)|'
                '((?:(?:\\d|[01]?\\d\\d|2[0-4]\\d|25[0-5])\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d|\\d)(?:\\/\\d{1,2})?)',
                url)
            return 1 if match else 0

        data['having_ip_address'] = data['url'].apply(lambda i: having_ip_address(i))

        X = data.drop(['url', 'domain'], axis=1)

        # Load the model and make predictions
        model = joblib.load('trained__model.pkl')
        prediction = model.predict(X)

        # Map predictions to result labels
        result_map = {0: "benign", 1: "defacement", 2: "phishing", 3: "malware"}
        result = result_map.get(prediction[0], "Unknown")

        return render_template('form.html', result=result)

    return render_template('form.html', result=None)



if __name__ == '__main__':
    app.run(debug=True)