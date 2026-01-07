from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
import joblib
import numpy as np
from urllib.parse import urlparse
import re
from difflib import SequenceMatcher
import requests
from bs4 import BeautifulSoup
import json
import os

app = Flask(__name__)
app.secret_key = "secret_key_for_demo" 


model = joblib.load('phishing_dt_pruned.pkl')

USERS_FILE = 'users_data.json'
COMMENTS_FILE = 'community_comments.json'

def extract_url_features(url):
    # Basic Parsing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    path = parsed.path
    query = parsed.query
    full_url = parsed.geturl()

    features = []
    
    
    
    features.append(full_url.count('.'))             # NumDots
    subdomains = len(hostname.split('.')) - 1
    features.append(subdomains)                      # SubdomainLevel
    features.append(len([p for p in path.split('/') if p])) # PathLevel
    features.append(len(full_url))                   # UrlLength
    features.append(full_url.count('-'))             # NumDash
    features.append(hostname.count('-'))             # NumDashInHostname
    features.append(1 if '@' in full_url else 0)     # AtSymbol
    features.append(1 if '~' in full_url else 0)     # TildeSymbol
    features.append(full_url.count('_'))             # NumUnderscore
    features.append(full_url.count('%'))             # NumPercent
    features.append(len(query.split('&')) if query else 0) # NumQueryComponents
    features.append(full_url.count('&'))             # NumAmpersand
    features.append(full_url.count('#'))             # NumHash
    features.append(len(re.findall(r'\d', full_url)))# NumNumericChars
    features.append(1 if not url.startswith('https') else 0) # NoHttps
    features.append(1 if re.search(r'[a-zA-Z0-9]{10,}', path) else 0) # RandomString
    features.append(1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname) else 0) # IpAddress
    features.append(1 if hostname.count('.') > 2 else 0) # DomainInSubdomains
    features.append(1 if 'http' in path else 0)      # DomainInPaths
    features.append(1 if 'https' in hostname else 0) # HttpsInHostname
    features.append(len(hostname))                   # HostnameLength
    features.append(len(path))                       # PathLength
    features.append(len(query))                      # QueryLength
    features.append(1 if '//' in path else 0)        # DoubleSlashInPath
    
    
   
    sensitive_words = ['login', 'bank', 'verify', 'secure', 'update', 'account', 'security','metamask', 'office365', 'webscr', 'signin', 'http']
    count = sum(1 for word in sensitive_words if word in full_url.lower())
    features.append(count*2) 
    
    brands = ['paypal', 'amazon', 'apple', 'metamask', 'wallets']
    features.append(1 if any(brand in hostname for brand in brands) else 0)
    
    
    features.append(1 if subdomains <= 2 else -1)    
    features.append(1 if len(full_url) < 54 else (0 if len(full_url) < 75 else -1))

    return features



def get_similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()

def heuristic_check(url):
    url = url.lower().strip()
    
   
    if url.startswith("http://"):
        return True 
    
    try:
        
        with open('blacklist.txt', 'r', encoding='utf-8') as f:
            blacklist = {line.strip().lower() for line in f if line.strip()}
        
        if url in blacklist:
            return True
    except FileNotFoundError:
        pass
    except UnicodeDecodeError:
        
        with open('blacklist.txt', 'r', encoding='latin-1') as f:
            blacklist = {line.strip().lower() for line in f if line.strip()}
        if url in blacklist:
            return True

    brands = ['microsoft', 'google', 'facebook', 'paypal', 'amazon', 'netflix', 'metamask', 'binance', 'youtu.be']
    legit_domains = ['microsoft.com', 'google.com', 'facebook.com', 'paypal.com', 'amazon.com', 'netflix.com', 'paypal.me', 'metamask.io', 'binance.com', 'paypal.com', 'youtube.com']
    suspicious_tlds = ['.ru', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']

    
    if any(url.endswith(tld) or (tld + "/") in url for tld in suspicious_tlds):
        return True

   
    for brand in brands:
        if brand in url:
            if not any(legit in url for legit in legit_domains):
                return True
        
        
        parts = re.split(r'\W+', url)
        for part in parts:
            if 0.8 <= get_similarity(part, brand) < 1.0:
                return True 

    return False

# --- User Data Handling (Persistence) ---
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_user(email, username, password):
    users = load_users()
    users[email] = {'username': username, 'password': password}
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)
        
# --- Community Comments Handling ---
def load_comments():
    if os.path.exists(COMMENTS_FILE):
        with open(COMMENTS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_comment(username, email, text):
    comments = load_comments()
    new_comment = {
        "name": username,
        "email": email, # Backend record ke liye
        "comment": text,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M")
    }
    comments.append(new_comment)
    with open(COMMENTS_FILE, 'w') as f:
        json.dump(comments, f, indent=4)

@app.route('/')
def index():
    return render_template('auth.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    users = load_users()
    if email in users:
        return "User already exists! <a href='/'>Go back</a>"
    
    save_user(email, username, password)
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')

    users = load_users()
    if email in users and users[email]['password'] == password:
        session['user'] = users[email]['username']
        session['email'] = email # Identifier for community page
        return redirect(url_for('home'))
    else:
        return "Invalid Credentials! <a href='/'>Try again</a>"

@app.route('/home')
def home():
    if 'user' not in session:
        return redirect(url_for('index'))
    return render_template('home.html', user=session['user'])

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/predict', methods=['POST'])
def predict():
    if 'user' not in session:
        return redirect(url_for('index'))

    url = request.form.get('url')
    if not url: 
        return redirect(url_for('home'))

    # Hybrid detection logic
    is_suspicious = heuristic_check(url)
    features = extract_url_features(url)
    input_data = np.array(features).reshape(1, -1)
    
    try:
        prob = model.predict_proba(input_data)[0][1] * 100 
    except:
        prob = 90.0 if model.predict(input_data)[0] == 1 else 10.0
        
    prediction = model.predict(input_data)[0]

    if is_suspicious or prediction == 1:
        final_result = "Phishing"
        risk_score = max(prob, 85.0) if is_suspicious else prob
    else:
        final_result = "Safe"
        risk_score = prob

    return render_template('home.html', 
                           prediction=final_result, 
                           prob=round(risk_score, 2),
                           analyzed_url=url, 
                           user=session['user'])

@app.route('/logout')
def logout():
    session.pop('user', None) 
    flash("You have been logged out safely.", "info")
    return redirect(url_for('index')) 

NEWS_FILE = 'cyber_news_cache.json'

def fetch_cyber_news():
    news_list = []
    try:
        # Hum 'The Hacker News' ka use kar rahe hain (Example)
        url = "https://thehackernews.com/"
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            # News articles dhoondna
            articles = soup.find_all('div', class_='body-post', limit=6)
            
            for art in articles:
                title = art.find('h2', class_='home-title').text.strip()
                link = art.find('a')['href']
                desc = art.find('div', class_='home-desc').text.strip()[:100] + "..."
                news_list.append({'title': title, 'link': link, 'description': desc})
            
            # Agar news mil gayi to cache mein save karlo
            if news_list:
                with open(NEWS_FILE, 'w') as f:
                    json.dump(news_list, f)
                return news_list
    except Exception as e:
        print(f"Scraping Error: {e}")
    
    # Fail-safe: Agar scraping fail hui ya block hui, to JSON se uthao
    if os.path.exists(NEWS_FILE):
        with open(NEWS_FILE, 'r') as f:
            return json.load(f)
    
    return [] # Agar kuch bhi nahi mila

@app.route('/news')
def news():
    if 'user' not in session:
        return redirect(url_for('index'))
    
    latest_news = fetch_cyber_news()
    return render_template('news.html', news_items=latest_news)

@app.route('/community', methods=['GET', 'POST'])
def community():
    if 'user' not in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        comment_text = request.form.get('comment')
        if comment_text:
            save_comment(session['user'], session['email'], comment_text)
            return redirect(url_for('community'))

    all_comments = load_comments()
    all_comments.reverse() # Latest comments upar dikhane ke liye
    return render_template('community.html', comments=all_comments)

@app.route('/delete_comment/<int:comment_index>')
def delete_comment(comment_index):
    if 'email' not in session:
        return redirect(url_for('index'))
    
    comments = load_comments()
    # Check karein ke index sahi hai aur user wahi hai jisne post kiya tha
    if 0 <= comment_index < len(comments):
        # Index reverse ho jata hai kyunki humne html mein reverse dikhaya tha
        # Isliye hum original list se sahi comment dhoondne ke liye ye karenge:
        original_idx = len(comments) - 1 - comment_index 
        
        if comments[original_idx]['email'] == session['email']:
            comments.pop(original_idx)
            with open(COMMENTS_FILE, 'w') as f:
                json.dump(comments, f, indent=4)
            flash("Comment deleted successfully!")
            
    return redirect(url_for('community'))

if __name__ == '__main__':
    app.run(debug=True)