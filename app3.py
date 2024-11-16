from flask import Flask, request, render_template
import numpy as np
import joblib
from urllib.parse import urlparse
import socket
import time
import dns.resolver
import textwrap
import Check as chP
import pickle

app = Flask(__name__)

# Load the trained model
model = joblib.load('Predict1/Predict/FinalPred.pkl')

# Define a function to check SSL certificate validity
import requests

def check_ssl(url):
    try:
        response = requests.get(url, verify=True)
        if response.status_code == 200:
            return True, None
        else:
            return False, "SSL certificate verification failed. Status code: {}".format(response.status_code)
    except requests.exceptions.RequestException as e:
        return False, "Failed to establish SSL connection: {}".format(str(e))


# Define a function to check DNS resolution
def check_dns_resolution(url):
    try:
        # Resolving domain to IP address
        ip_address = socket.gethostbyname(urlparse(url).netloc)
        return ip_address
    except socket.gaierror:
        return None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    # Get URL input from the user
    url = request.form['url']
    
    # Extract features from the URL
    vals = chP.extract_featuresS(url)
    x = [vals[key] for key in vals.keys()]
    model_input = (np.array(x, dtype=object)).reshape(1, -1)

    # Make prediction using the model
    pred_proba = model.predict_proba(model_input)
    phishing_probability = str(pred_proba[0][1] * 100)  # Convert to percentage

    # Perform additional checks
    ssl_validity = check_ssl(url)
    dns_resolution = check_dns_resolution(url)
    # Add more checks as needed
    
    # Return prediction result and additional information to the user
    return render_template('result.html', 
                           url=url,
                           p=phishing_probability,
                           ssl_validity=ssl_validity,
                           dns_resolution=dns_resolution)

if __name__ == '__main__':
    app.run(debug=True)