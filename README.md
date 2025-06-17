# Real-Time Steam Phishing Proxy (Educational Demo)

This project is a sophisticated phishing toolkit created for educational and research purposes. It demonstrates how a real-time, man-in-the-middle proxy can be set up to intercept credentials and bypass 2-Factor Authentication (2FA) on a modern, JavaScript-heavy website like Steam.

**This tool is intended strictly for learning and authorized security testing. Using it for any unauthorized or malicious activity is illegal and unethical.**

---

## Core Features

- **Full Site Proxy:** Dynamically proxies the Steam login page, rewriting all links, forms, and scripts on the fly to keep the user within the phishing environment.
- **Real-Time Credential Capture:** Intercepts username and password submissions without alerting the user.
- **Automated Backend Login:** Uses a headless Chrome browser (via Selenium) in a background thread to perform a live login with the captured credentials.
- **Advanced 2FA Handling:**
    - Detects if a Steam Guard Mobile Authenticator (push notification) is required and waits for the user to approve it on their phone.
    - If a code is required instead (Steam Guard or email), it dynamically serves a page to capture the 2FA code from the victim.
- **Session Hijacking:** Successfully captures all session cookies after a valid login, which can be used to take over the authenticated session.
- **Sophisticated User Experience:**
    - Displays a realistic "Authenticating..." page that polls the server for the live login status.
    - Redirects the user to the legitimate Steam website upon successful authentication to complete the illusion.
- **Data Persistence:** Stores captured credentials, 2FA codes, status, and session cookies in a local SQLite database.
- **Automatic Database Migration:** The application automatically updates the database schema on startup, ensuring compatibility with new code changes without losing data.

## Technology Stack

- **Backend:** Python, Flask
- **Automation:** Selenium with `undetected-chromedriver`
- **Frontend:** HTML, CSS, JavaScript (for injection and polling)
- **Database:** SQLite

## How It Works

1.  **Proxying:** The Flask server listens for incoming requests. When the victim visits the phishing URL, the server fetches the real Steam login page.
2.  **Rewriting:** Before sending the page to the victim, the server uses BeautifulSoup to parse the HTML and rewrite all `href`, `src`, and `action` attributes. This ensures all subsequent requests from the victim's browser are routed back through the proxy.
3.  **Credential Injection:** A custom JavaScript payload is injected into the page to capture credentials when the user clicks the "Sign in" button.
4.  **Background Automation:** Upon receiving credentials, a background thread starts a Selenium WebDriver instance. It navigates to the real Steam login page, enters the credentials, and handles any 2FA prompts that appear.
5.  **Status Polling:** The victim is redirected to a waiting page which repeatedly asks the server for the status of the background login attempt.
6.  **Success/Failure:**
    - On **success**, the server saves the session cookies, updates the status in the database, and the victim is redirected to the real `steamcommunity.com`.
    - On **failure**, the error is logged, and the victim sees an error message.

## Setup & Usage

1.  **Clone the repository:**
    ```bash
    git clone <your-repo-url>
    cd <repo-directory>
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    # For Windows
    python -m venv venv
    .\venv\Scripts\activate

    # For macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the application:**
    ```bash
    python app.py
    ```

5.  Open a web browser and navigate to `http://127.0.0.1:5000`. You will see the proxied Steam login page.

---

### **Ethical Disclaimer**

The creator of this project is not responsible for any misuse or damage caused by this program. This is a personal project developed for educational purposes to understand and demonstrate cybersecurity principles. **Do not use it for illegal purposes.** 