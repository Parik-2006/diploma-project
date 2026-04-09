# ⚡ MaliciousBot: Phishing URL Detection Engine

> **A Next-Generation Phishing & Malicious URL Detection System.**
> *Designed for Web Security, Cyber Threat Analysis, and Real-Time Protection.*

---

## 📖 Project Objective

Modern web environments face constant threats from phishing and malicious URLs:
* **Manual Blacklists:** Quickly become outdated and miss new threats.
* **Signature-Based Detection:** Fails against zero-day and obfuscated attacks.

**The Solution:**
The **MaliciousBot** engine leverages machine learning to analyze and classify URLs in real-time. It combines feature extraction, statistical analysis, and predictive modeling to provide robust protection against evolving threats.

---

## ⚙️ Detection Algorithm

The engine evaluates each URL using a composite score ($S$) based on multiple features:

$$S = (W_{lex} \times F_{lexical}) + (W_{host} \times F_{host}) + (W_{meta} \times F_{meta})$$

* **$W_{lex}$ (Lexical Weight):** Analyzes suspicious patterns in the URL string.
* **$W_{host}$ (Host Weight):** Checks domain reputation, age, and IP anomalies.
* **$W_{meta}$ (Metadata Weight):** Considers WHOIS, SSL, and other metadata.

---

## 🌍 Real-World Scenarios

This project demonstrates MaliciousBot's effectiveness in four key domains:

| Domain | The Problem | The MaliciousBot Solution |
| :--- | :--- | :--- |
| **🏦 Online Banking** | Phishing links steal credentials. | **Real-Time Detection:** Blocks suspicious URLs before login. |
| **🎓 E-Learning** | Students targeted by fake portals. | **Automated Screening:** Flags malicious links in course content. |
| **🛒 E-Commerce** | Fake stores trick shoppers. | **Domain Analysis:** Identifies and blocks scam sites. |
| **💼 Enterprise Email** | Employees receive phishing emails. | **Bulk Scanning:** Scans and filters URLs in incoming mail. |

---

## 🛠️ Tech Stack

* **Backend:** Python (Django)
* **Algorithm:** Machine Learning (Scikit-learn, Pandas)
* **Frontend:** HTML5, CSS3, JavaScript (Bootstrap)
* **Visualization:** Matplotlib, Chart.js (for analytics)

---

## 🚀 How to Run Locally

1. **Clone the Repository**
    ```bash
    git clone https://github.com/YOUR-USERNAME/maliciousbot.git
    cd maliciousbot
    ```

2. **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3. **Run the Server**
    ```bash
    python manage.py runserver
    ```

4. **Open in Browser**
    Visit `http://127.0.0.1:8000`

---

## ☁️ Deployment

This project is deployed on **Render**.
1. Push code to GitHub.
2. Connect your repository to Render.
3. Render automatically deploys your Django app using `render.yaml`.

**Live Demo:** [MaliciousBot on Render](https://diploma-project-rwht.onrender.com)

---

### 📄 License

This project is for educational research purposes.

## 🤝 Contributing & Issues

This project is open for viewing. **Direct changes are restricted.**

* **Found a bug?** Please [Open a New Issue](https://github.com/YOUR-USERNAME/maliciousbot/issues/new) and describe the problem.
* **Want to fix it?** Please Fork the repo and submit a Pull Request (PR) for review.

---

## 👥 Team

- Appu Gowda GC
- Bhuvan Raj H
- Ajay Kumar P

---
