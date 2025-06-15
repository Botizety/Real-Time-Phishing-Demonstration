# Advanced Phishing Toolkit & Reverse Proxy Server

### 🔴 Important Ethical Disclaimer
**This project was developed for educational purposes only.** It is a tool intended for security professionals and students to understand the mechanics of advanced phishing attacks and reverse proxying. Do not use this tool against any system or website that you do not own or have explicit, written permission to test. The author is not responsible for any misuse of this software.

---

## Project Summary

This project is a standalone reverse proxy server, built in Python and Flask, designed to simulate advanced phishing campaigns. It can clone dynamic, JavaScript-rendered websites in real-time by proxying live traffic, rewriting HTML content on the fly to capture form submissions. This tool effectively demonstrates how modern phishing attacks can bypass simple defenses by acting as a man-in-the-middle, serving live content from the target site to the user.

## Key Features

- **Standalone Reverse Proxy:** Runs as a single Flask application, requiring no complex setup.
- **Live Content Serving:** Fetches and serves content directly from the target site in real-time.
- **Dynamic HTML Rewriting:** Uses BeautifulSoup to parse live HTML and rewrite links, image sources, and form actions to keep the user within the proxy environment.
- **Credential Capture:** Intercepts `POST` requests from login forms and logs captured data to a local text file.
- **Publicly Deployable:** Can be easily exposed to the public internet for realistic testing scenarios using `ngrok`.

## The Development Journey & Challenges Overcome

The development of this tool was an iterative process that involved diagnosing and bypassing multiple layers of modern web application security.

- **Initial Failure:** An early version using simple `requests` and `BeautifulSoup` to create a static clone failed against modern targets like Steam, because their login pages are rendered dynamically with JavaScript.

- **Advanced Interception:** To overcome this, the project was re-architected into a **Man-in-the-Middle (MITM)** tool using `mitmproxy`. This allowed for the interception of live traffic and the injection of custom JavaScript to hijack form submission events.

- **Diagnosing Real-World Defenses:** While testing with `mitmproxy`, several professional-grade security features were encountered and analyzed:
    - **HTTP Strict Transport Security (HSTS):** A browser-level security policy that prevents users from ignoring certificate warnings. This required learning specific browser bypass techniques used by security testers.
    - **Server-Side Anti-Botting:** Sophisticated targets like Facebook were found to use redirect loops to trap and block non-browser traffic, demonstrating the limitations of script-based requests.

- **Final Architecture:** The final version is a standalone Flask application that acts as its own reverse proxy. This architecture provides the most stable and portable solution, successfully cloning medium-difficulty HTTPS sites like the GitHub login page in a real-world test scenario.

## Setup and Usage

This project requires Python and the libraries listed in `requirements.txt`.

1.  **Clone the Repository:**
    ```bash
    git clone <your-repo-url>
    cd <your-repo-folder>
    ```

2.  **Set up Virtual Environment & Install Dependencies:**
    ```bash
    # Create and activate a virtual environment
    python -m venv venv
    .\venv\Scripts\activate

    # Install required libraries
    pip install -r requirements.txt
    ```

3.  **Configure the Target:**
    * Open `app.py` and modify the `TARGET_HOST` and `TARGET_PROTOCOL` variables to your desired test site.

4.  **Run the Server:**
    * In your first terminal, start the Flask application.
    ```bash
    python app.py
    ```

5.  **Expose to the Internet (Optional, for "real-world" testing):**
    * In a second terminal, use `ngrok` to create a public URL for your local server.
    ```bash
    ngrok http 5000
    ```
    * Use the public `https://...` URL provided by `ngrok` as your phishing link.

6.  **Check Results:**
    * Captured credentials will be saved to `captured_credentials.txt` in the project directory.

## Technologies Used

- **Python**
- **Flask**
- **Requests**
- **BeautifulSoup4**
- **ngrok**
- **mitmproxy** (for research and development)