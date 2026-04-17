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

@app.route('/')
def index():
	return render_template('form.html')

@app.route('/process', methods=['GET', 'POST',])
def process():
	print("hi")
	data = request.form['name']
	data= {"url":[data]}
	data = pd.DataFrame(data)

	data['url_len'] = data['url'].apply(lambda x: len(str(x)))

	def process_tld(url):
		try:
			#         Extract the top level domain (TLD) from the URL given
			res = get_tld(url, as_object=True, fail_silently=False, fix_protocol=True)
			pri_domain = res.parsed_url.netloc
		except:
			pri_domain = None
		return pri_domain

	data['domain'] = data['url'].apply(lambda i: process_tld(i))
	feature = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']
	for a in feature:
		data[a] = data['url'].apply(lambda i: i.count(a))
	data.head()

	def abnormal_url(url):
		hostname = urlparse(url).hostname
		hostname = str(hostname)
		match = re.search(hostname, url)
		if match:
			# print match.group()
			return 1
		else:
			# print 'No matching pattern found'
			return 0

	data['abnormal_url'] = data['url'].apply(lambda i: abnormal_url(i))

	data.head()

	def httpSecure(url):
		htp = urlparse(url).scheme  # It supports the following URL schemes: file , ftp , gopher , hdl ,
		# http , https ... from urllib.parse
		match = str(htp)
		if match == 'https':
			# print match.group()
			return 1
		else:
			# print 'No matching pattern found'
			return 0

	data['https'] = data['url'].apply(lambda i: httpSecure(i))
	data.head(20)

	def digit_count(url):
		digits = 0
		for i in url:
			if i.isnumeric():
				digits = digits + 1
		return digits

	data['digits'] = data['url'].apply(lambda i: digit_count(i))
	data.head()

	def letter_count(url):
		letters = 0
		for i in url:
			if i.isalpha():
				letters = letters + 1
		return letters

	data['letters'] = data['url'].apply(lambda i: letter_count(i))

	def Shortining_Service(url):
		match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
						  'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
						  'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
						  'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
						  'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
						  'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
						  'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
						  'tr\.im|link\.zip\.net',
						  url)
		if match:
			return 1
		else:
			return 0

	data['Shortining_Service'] = data['url'].apply(lambda x: Shortining_Service(x))

	def having_ip_address(url):
		match = re.search(
			'(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
			'([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
			'(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
			'([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4 with port
			'((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
			'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
			'([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
			'((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', url)  # Ipv6
		if match:
			return 1
		else:
			return 0

	data['having_ip_address'] = data['url'].apply(lambda i: having_ip_address(i))
	X = data.drop(['url', 'domain'], axis=1)
	print(X)


	model = joblib.load('trained__model.pkl')
	# In[51]:

	prediction = model.predict(X)

	# In[52]:

	if prediction == 0:
		result="bengin"
	if prediction == 1:
		result="defacement"
	if prediction == 2:
		result="phishing"
	if prediction == 3:
		result="malware"

	return jsonify({'name': result})


# In[ ]:


if __name__ == '__main__':
	app.run(debug=True)

