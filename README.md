# WAF Simulator — Web Application Firewall

A rule-based Web Application Firewall that detects and blocks SQL Injection, XSS, Path Traversal, and Brute Force attacks in real time.

## Features
- Real-time attack detection using regex rules
- WAF ON/OFF toggle for demo comparison
- Live dashboard with attack statistics
- Traffic log showing every request
- Interactive attack terminal
- Demo target app (ShopEase)

## Tech Stack
- Python 3.11
- Flask
- SQLite
- Regular Expressions
- HTML / CSS / JavaScript

## How to Run

pip install -r requirements.txt
python app.py

Open https://waf-simulator-etcj.onrender.com/

## Demo
1. Visit /site/ — target ShopEase site
2. Type attack in URL: /site/search?q=' OR '1'='1 → Blocked
3. Visit /terminal — test curl commands
4. Visit /traffic — see all requests
5. Visit /dashboard — attack statistics

## Author
Mandar Kulkarni — Final Year Project
