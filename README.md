# Ethical Phishing & Web Security Analysis Tool

**Author:** [Your Name/GitHub Username]  
**University:** SIIT, Thammasat University  
**Major:** Computer Engineering & Cyber Security

---

### **Disclaimer: For Educational Use Only**

This tool was developed as a personal project for educational and research purposes. It is designed to demonstrate the mechanics of Man-in-the-Middle (MITM) attacks, credential harvesting, and session hijacking in a controlled environment. 

**Under no circumstances should this tool be used for any malicious or illegal activities.** The author is not responsible for any misuse of this software. Using this tool against any system without explicit, prior consent is illegal and unethical.

---

## Project Overview

This project is a full-proxy web application written in Python. It is designed to intercept and analyze HTTP/HTTPS traffic between a user and a target website. The primary goal was to gain a practical understanding of web security vulnerabilities and the countermeasures used to prevent them.

By building this tool, I was able to explore real-world attack vectors and the sophisticated security systems deployed by major web platforms.

## Key Technical Features

*   **Full-Proxy Architecture:** Built using Flask, the application acts as a central proxy, forwarding all requests from the user to the target server and sending the responses back to the user.
*   **Dynamic HTML Rewriting:** Utilizes `BeautifulSoup` to parse and rewrite all HTML content on-the-fly. This ensures that all links (`href`), sources (`src`), and form actions are correctly proxied, keeping the user within the phishing environment.
*   **Credential & Cookie Harvesting:** Successfully intercepts and logs username/password combinations and authentication cookies submitted via login forms.
*   **Secure Data Logging:** All captured data is stored locally in a structured SQLite database for later analysis.
*   **Investigation of Anti-Bot Measures:** The project initially included advanced browser automation with Selenium and `undetected-chromedriver` to study how websites like Steam detect and block automated logins. This provided valuable insight into modern browser fingerprinting and security tactics.

## Core Technologies Used

*   **Backend:** Python, Flask
*   **HTML Parsing:** BeautifulSoup4
*   **Database:** SQLite3
*   **HTTP Requests:** `requests` library

## Setup and Installation

1.  **Clone the repository:**
    ```bash
    git clone [your-repository-url]
    cd [repository-name]
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    # For Windows
    python -m venv venv
    venv\Scripts\activate

    # For macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: You will need to create a `requirements.txt` file. See below.)*

4.  **Run the application:**
    ```bash
    python app.py
    ```
    The server will start on `http://127.0.0.1:5000`. Open this URL in your browser to see the proxied site. Captured credentials can be viewed at `http://127.0.0.1:5000/results`.

--- 