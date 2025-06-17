<div align="center">
  <h1 align="center">Real-Time Phishing Demonstration</h1>
  <p align="center">
    <strong>A sophisticated phishing toolkit for educational and research purposes.</strong>
  </p>
</div>

> [!CAUTION]
> **This project was created for educational purposes only.** It demonstrates how a real-time, man-in-the-middle phishing attack works. Using this tool for any unauthorized or malicious activity is **illegal and strictly prohibited**. The author is not responsible for any misuse or damage caused by this program.

---

This project showcases a real-time phishing proxy that targets the Steam login page. It's designed to demonstrate advanced phishing techniques, including live credential interception, dynamic site rewriting, and handling of 2-Factor Authentication (2FA). It serves as a practical example of modern cybersecurity threats for students, researchers, and professionals.

## Key Features

- **Full Site Proxy:** Dynamically proxies the Steam login page, rewriting all links, forms, and scripts on the fly to keep the user within the phishing environment.
- **Real-Time Credential Capture:** Intercepts username and password submissions transparently.
- **Automated Backend Login:** Uses a headless Chrome browser (via Selenium) in a background thread to perform a live login with the captured credentials.
- **Advanced 2FA Handling:**
    - Detects if Steam Guard Mobile Authenticator (push notification) is required and waits for the user to approve it.
    - If a code is required (from authenticator or email), it serves a dynamic page to capture the 2FA code from the victim.
- **Session Hijacking:** Captures all session cookies after a valid login, which can be used to take over the authenticated session.
- **Sophisticated User Experience:**
    - Displays a realistic "Authenticating..." page that polls the server for the live login status.
    - Redirects the user to the legitimate Steam website upon successful authentication to complete the illusion.
- **Data Persistence:** Stores captured credentials, 2FA codes, status, and session cookies in a local SQLite database.
- **Automatic Database Migration:** The application automatically updates the database schema on startup, ensuring compatibility with new code changes without losing data.

## How It Works

The attack flow is designed to be seamless and convincing for the victim.

1.  **Proxying:** The victim navigates to the phishing URL. The Flask server fetches the real Steam login page content.
2.  **Rewriting:** Before serving the page, the application uses `BeautifulSoup` to parse the HTML and rewrite all `href`, `src`, and `action` attributes. This ensures all subsequent requests (for CSS, images, scripts) are routed back through the proxy.
3.  **Injection:** A custom JavaScript payload (`obfuscated.js`) is injected into the page. This script listens for the "Sign in" button click to capture credentials.
4.  **Submission & Automation:**
    - The victim submits their credentials.
    - The Flask server receives the credentials and immediately starts a background Selenium WebDriver instance.
    - The victim is redirected to a waiting page (`authenticating.html`) that realistically mimics the Steam login process.
5.  **Live Login & 2FA:**
    - The Selenium bot navigates to the real Steam login page, enters the credentials, and handles any 2FA prompts that appear (waiting for push approval or asking the victim for a code).
    - The waiting page continuously polls a status endpoint (`/get_login_status`) to check the progress of the backend login.
6.  **Success & Redirect:**
    - On successful login, the bot extracts the session cookies.
    - The status is updated in the database, the polling from the victim's page gets a "success" response, and the victim is redirected to the real `steamcommunity.com`, making the phishing attempt appear legitimate.

## Technology Stack

- **Backend:** Python, Flask
- **Automation & Scraping:** Selenium with `undetected-chromedriver`
- **HTML Parsing/Rewriting:** BeautifulSoup4
- **Frontend:** HTML, CSS, JavaScript
- **Database:** SQLite

## Project Structure

```
.
├── app.py                  # Main Flask application, contains all backend logic.
├── requirements.txt        # Project dependencies.
├── obfuscated.js           # Obfuscated JavaScript for credential capture.
├── instance/
│   └── credentials.db      # SQLite database for storing captured data.
├── templates/
│   ├── login.html          # The proxied Steam login page.
│   ├── 2fa.html            # Page to capture 2FA code.
│   └── authenticating.html # Waiting page with spinner shown to the user.
└── README.md               # This file.
```

## Setup & Usage

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/your-username/Real-Time-Phishing-Demonstration.git
    cd Real-Time-Phishing-Demonstration
    ```

2.  **Create and Activate a Virtual Environment**
    ```bash
    # On Windows
    python -m venv venv
    .\venv\Scripts\activate

    # On macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```
    *Note: `undetected-chromedriver` will automatically download the correct `chromedriver` for your installed version of Chrome.*

4.  **Run the Application**
    ```bash
    python app.py
    ```

5.  **Access the Phishing Page**
    Open a web browser and navigate to `http://127.0.0.1:5000`. You will see the proxied Steam login page. Any credentials entered will be processed by the backend.

---

### **Ethical Disclaimer**

This project is a personal portfolio piece developed to demonstrate skills in web technologies, automation, and cybersecurity. The creator does not condone or support any malicious use of this code. It is intended for educational purposes, responsible disclosure, and authorized security testing only. **Using this software for any illegal activity is a serious offense.** 