import os
import uuid
import json
import time
import logging
from datetime import datetime, timedelta
import threading
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from werkzeug.utils import secure_filename
from email.parser import BytesParser
from email.policy import default
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, unquote
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max file size

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'eml', 'msg', 'txt'}

# Analysis sessions storage (in production, use Redis or database)
analysis_sessions = {}

# URL reputation cache
url_cache = {}
CACHE_EXPIRY = 3600  # 1 hour

ANALYSIS_STEPS = {
    1: 'extract',
    2: 'checks',
    3: 'url_reputation',
    4: 'score'
}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_urls_from_text(text):
    """Extract URLs from text using regex"""
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    return url_pattern.findall(text)

def parse_email_content(email_content):
    """Parse email content and extract relevant information"""
    try:
        # Parse email
        msg = BytesParser(policy=default).parsebytes(email_content.encode('utf-8'))
        
        # Extract basic info
        from_header = msg.get('From', '')
        reply_to = msg.get('Reply-To', '')
        subject = msg.get('Subject', '')
        to_header = msg.get('To', '')
        authentication_results = msg.get('Authentication-Results', '')
        received_headers = msg.get_all('Received', [])
        
        # Extract body content
        body_text = ''
        body_html = ''
        links = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                
                try:
                    if content_type == "text/plain":
                        body_text += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    elif content_type == "text/html":
                        html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        body_html += html_content
                        # Extract links from HTML
                        soup = BeautifulSoup(html_content, 'html.parser')
                        for link in soup.find_all('a', href=True):
                            links.append(link['href'])
                except Exception as e:
                    logger.warning(f"Error parsing email part: {e}")
                    continue
        else:
            # Single part email
            content_type = msg.get_content_type()
            try:
                if content_type == "text/plain":
                    body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                elif content_type == "text/html":
                    html_content = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                    body_html = html_content
                    soup = BeautifulSoup(html_content, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        links.append(link['href'])
            except Exception as e:
                logger.warning(f"Error parsing single part email: {e}")
        
        # Extract links from plain text as well
        if body_text:
            text_links = extract_urls_from_text(body_text)
            links.extend(text_links)
        
        # Remove duplicates and filter valid URLs
        valid_links = []
        for link in links:
            try:
                parsed = urlparse(link)
                if parsed.scheme and parsed.netloc:
                    valid_links.append(link)
            except:
                continue
        
        # Extract attachments
        attachments = []
        for part in msg.walk():
            if part.get_content_disposition() and 'attachment' in part.get_content_disposition():
                filename = part.get_filename()
                if filename:
                    attachments.append({
                        'filename': filename,
                        'content_type': part.get_content_type(),
                        'size': len(part.get_payload(decode=True)) if part.get_payload(decode=True) else 0
                    })
        
        return {
            'from': from_header,
            'reply_to': reply_to,
            'subject': subject,
            'to': to_header,
            'authentication_results': authentication_results,
            'received_headers': received_headers,
            'body_text': body_text,
            'body_html': body_html,
            'links': list(set(valid_links)),  # Remove duplicates
            'attachments': attachments
        }
    except Exception as e:
        logger.error(f"Error parsing email: {e}")
        raise

class PhishingScorer:
    def __init__(self):
        self.score = 0
        self.findings = []
        
        # Urgency keywords
        self.urgency_keywords = [
            'urgent', 'immediate action', 'account suspended', 'verify now',
            'payment issue', 'login required', 'expire soon', 'act now',
            'limited time', 'final notice', 'suspended', 'locked', 'verify',
            'confirm', 'update', 'secure', 'protect'
        ]
        
        # Suspicious file extensions
        self.dangerous_extensions = [
            '.exe', '.scr', '.js', '.vbs', '.bat', '.cmd', '.com',
            '.pif', '.jar', '.zip', '.rar'
        ]
        
        # Free email providers
        self.free_email_providers = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'aol.com', 'icloud.com', 'mail.com', 'protonmail.com'
        ]
    
    def check_header_spoofing(self, email_data):
        """Check for header spoofing indicators"""
        score = 0
        findings = []
        
        # Check display name vs actual domain mismatch
        from_header = email_data.get('from', '')
        if from_header:
            # Extract display name and email
            import email.utils
            parsed_from = email.utils.parseaddr(from_header)
            display_name = parsed_from[0]
            email_address = parsed_from[1]
            
            if display_name and email_address:
                # Check if display name suggests official company but email is from free provider
                official_keywords = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'netflix', 'bank']
                display_lower = display_name.lower()
                email_domain = email_address.split('@')[1].lower() if '@' in email_address else ''
                
                for keyword in official_keywords:
                    if keyword in display_lower and email_domain in self.free_email_providers:
                        score += 20
                        findings.append(f"Display name '{display_name}' suggests official company but uses free email provider")
                        break
        
        # Check Reply-To mismatch
        reply_to = email_data.get('reply_to', '')
        if reply_to and from_header:
            from_domain = from_header.split('@')[1].lower() if '@' in from_header else ''
            reply_domain = reply_to.split('@')[1].lower() if '@' in reply_to else ''
            
            if from_domain and reply_domain and from_domain != reply_domain:
                score += 15
                findings.append(f"Reply-To domain '{reply_domain}' differs from From domain '{from_domain}'")
        
        # Check authentication results
        auth_results = email_data.get('authentication_results', '')
        if auth_results:
            if 'spf=fail' in auth_results.lower() or 'spf=none' in auth_results.lower():
                score += 10
                findings.append("SPF authentication failed or missing")
            
            if 'dkim=fail' in auth_results.lower() or 'dkim=none' in auth_results.lower():
                score += 10
                findings.append("DKIM authentication failed or missing")
            
            if 'dmarc=fail' in auth_results.lower() or 'dmarc=none' in auth_results.lower():
                score += 10
                findings.append("DMARC authentication failed or missing")
            
            if 'spf=pass' in auth_results.lower():
                score -= 5
                findings.append("SPF authentication passed (positive indicator)")
        
        return score, findings
    
    def check_sender_anomalies(self, email_data):
        """Check for sender anomalies"""
        score = 0
        findings = []
        
        from_header = email_data.get('from', '')
        if not from_header:
            score += 10
            findings.append("Missing From header")
            return score, findings
        
        # Extract email domain
        import email.utils
        parsed_from = email.utils.parseaddr(from_header)
        email_address = parsed_from[1]
        
        if '@' in email_address:
            domain = email_address.split('@')[1].lower()
            
            # Check for typosquatting/homoglyphs
            legitimate_domains = [
                'paypal.com', 'amazon.com', 'microsoft.com', 'google.com',
                'apple.com', 'netflix.com', 'linkedin.com', 'facebook.com',
                'twitter.com', 'instagram.com', 'bankofamerica.com', 'wellsfargo.com'
            ]
            
            for legit_domain in legitimate_domains:
                # Check for character substitution (homoglyphs)
                if self.is_typosquatting(domain, legit_domain):
                    score += 20
                    findings.append(f"Potential typosquatting: '{domain}' vs legitimate '{legit_domain}'")
                    break
            
            # Check for free email provider in official context
            subject = email_data.get('subject', '').lower()
            if any(keyword in subject for keyword in ['invoice', 'payment', 'account', 'statement']):
                if domain in self.free_email_providers:
                    score += 15
                    findings.append(f"Free email provider '{domain}' used for official-looking communication")
        
        return score, findings
    
    def is_typosquatting(self, domain, legitimate_domain):
        """Check if domain is typosquatting a legitimate domain"""
        # Simple typosquatting detection
        if domain == legitimate_domain:
            return False
        
        # Check for character substitution (homoglyphs)
        homoglyphs = {
            'o': '0', '0': 'o',
            'l': '1', '1': 'l', 'I': 'l',
            'a': '@', '@': 'a',
            'e': '3', '3': 'e'
        }
        
        # Check for character swaps
        if len(domain) == len(legitimate_domain):
            diff_count = 0
            for i in range(len(domain)):
                if domain[i] != legitimate_domain[i]:
                    # Check if it's a homoglyph substitution
                    if domain[i] in homoglyphs and homoglyphs[domain[i]] == legitimate_domain[i]:
                        diff_count += 1
                    else:
                        return False
            return diff_count <= 2 and diff_count > 0
        
        # Check for extra characters
        if abs(len(domain) - len(legitimate_domain)) <= 2:
            # Simple Levenshtein distance check
            if self.levenshtein_distance(domain, legitimate_domain) <= 2:
                return True
        
        return False
    
    def levenshtein_distance(self, s1, s2):
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def check_urgency_language(self, email_data):
        """Check for urgency/threat language"""
        score = 0
        findings = []
        
        subject = email_data.get('subject', '').lower()
        body_text = email_data.get('body_text', '').lower()
        
        combined_text = subject + ' ' + body_text
        
        urgency_count = 0
        for keyword in self.urgency_keywords:
            if keyword in combined_text:
                urgency_count += 1
                findings.append(f"Urgency keyword found: '{keyword}'")
        
        if urgency_count >= 3:
            score += 15
        elif urgency_count >= 1:
            score += 5 * urgency_count
        
        return score, findings
    
    def check_body_red_flags(self, email_data):
        """Check for body content red flags"""
        score = 0
        findings = []
        
        body_text = email_data.get('body_text', '').lower()
        body_html = email_data.get('body_html', '').lower()
        combined_body = body_text + ' ' + body_html
        
        # Check for credential requests
        credential_keywords = ['password', 'login', 'username', 'account', 'verify identity']
        for keyword in credential_keywords:
            if keyword in combined_body:
                score += 10
                findings.append(f"Credential request detected: '{keyword}'")
                break
        
        # Check for generic greetings
        generic_greetings = ['dear customer', 'dear user', 'dear member', 'hello customer']
        for greeting in generic_greetings:
            if greeting in combined_body:
                score += 5
                findings.append(f"Generic greeting detected: '{greeting}'")
                break
        
        # Check for threats
        threat_keywords = ['account will be closed', 'suspended', 'terminated', 'legal action']
        for threat in threat_keywords:
            if threat in combined_body:
                score += 10
                findings.append(f"Threat detected: '{threat}'")
                break
        
        # Check for too-good-to-be-true offers
        offer_keywords = ['congratulations', 'winner', 'lottery', 'inheritance', 'million dollars']
        offer_count = 0
        for offer in offer_keywords:
            if offer in combined_body:
                offer_count += 1
        
        if offer_count >= 2:
            score += 10
            findings.append("Too-good-to-be-true offers detected")
        
        return score, findings
    
    def check_suspicious_links(self, email_data):
        """Check for suspicious links"""
        score = 0
        findings = []
        
        links = email_data.get('links', [])
        
        # Check for shortened URLs
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link']
        
        for link in links:
            try:
                parsed = urlparse(link)
                domain = parsed.netloc.lower()
                
                # Check for URL shorteners
                for shortener in shorteners:
                    if shortener in domain:
                        score += 15
                        findings.append(f"Shortened URL detected: {link}")
                        break
                
                # Check for display text vs actual URL mismatch (would need HTML parsing)
                # This is a simplified check
                if 'phishing' in link.lower() or 'malware' in link.lower():
                    score += 20
                    findings.append(f"Suspicious URL detected: {link}")
                
            except Exception as e:
                logger.warning(f"Error parsing URL {link}: {e}")
                continue
        
        return score, findings
    
    def check_attachments(self, email_data):
        """Check for suspicious attachments"""
        score = 0
        findings = []
        
        attachments = email_data.get('attachments', [])
        
        for attachment in attachments:
            filename = attachment.get('filename', '').lower()
            
            # Check for dangerous extensions
            for ext in self.dangerous_extensions:
                if filename.endswith(ext):
                    score += 20
                    findings.append(f"Dangerous attachment: '{filename}'")
                    break
            
            # Check for suspicious names
            suspicious_names = ['invoice', 'receipt', 'statement', 'document']
            for name in suspicious_names:
                if name in filename and filename.endswith('.exe'):
                    score += 15
                    findings.append(f"Suspicious attachment name: '{filename}'")
                    break
        
        return score, findings
    
    def calculate_score(self, email_data):
        """Calculate overall phishing risk score"""
        self.score = 0
        self.findings = []
        
        # Run all checks
        checks = [
            self.check_header_spoofing,
            self.check_sender_anomalies,
            self.check_urgency_language,
            self.check_body_red_flags,
            self.check_suspicious_links,
            self.check_attachments
        ]
        
        for check in checks:
            try:
                score, findings = check(email_data)
                self.score += score
                self.findings.extend(findings)
            except Exception as e:
                logger.error(f"Error in check {check.__name__}: {e}")
        
        # Ensure score is within 0-100 range
        self.score = max(0, min(100, self.score))
        
        return self.score, self.findings

def get_url_reputation(url):
    """Check URL reputation using external APIs"""
    # Check cache first
    if url in url_cache:
        cached_result = url_cache[url]
        if datetime.now() < cached_result.get('expires_at', datetime.now()):
            return cached_result
    
    result = {
        'google_safe_browsing': 'unknown',
        'virustotal': 'unknown',
        'detection_count': 0,
        'cached_at': datetime.now(),
        'expires_at': datetime.now() + timedelta(seconds=CACHE_EXPIRY)
    }
    
    # Google Safe Browsing API check
    google_api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    if google_api_key:
        try:
            google_result = check_google_safe_browsing(url, google_api_key)
            result['google_safe_browsing'] = google_result
        except Exception as e:
            logger.error(f"Google Safe Browsing API error: {e}")
    
    # VirusTotal API check
    virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if virustotal_api_key:
        try:
            vt_result, detection_count = check_virustotal(url, virustotal_api_key)
            result['virustotal'] = vt_result
            result['detection_count'] = detection_count
        except Exception as e:
            logger.error(f"VirusTotal API error: {e}")
    
    # Cache result
    url_cache[url] = result
    return result

def check_google_safe_browsing(url, api_key):
    """Check URL against Google Safe Browsing API"""
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    response = requests.post(api_url, json=payload, timeout=10)
    
    if response.status_code == 200:
        data = response.json()
        if 'matches' in data and len(data['matches']) > 0:
            return 'malicious'
        return 'safe'
    
    return 'error'

def check_virustotal(url, api_key):
    """Check URL against VirusTotal API"""
    # First, submit URL for scanning
    submit_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded"
    }
    
    # Submit URL
    response = requests.post(submit_url, data=f"url={url}", headers=headers, timeout=10)
    
    if response.status_code == 200:
        data = response.json()
        if 'data' in data and 'id' in data['data']:
            analysis_id = data['data']['id']
            
            # Wait a bit for analysis
            time.sleep(2)
            
            # Get analysis results
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers, timeout=10)
            
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                if 'data' in analysis_data and 'attributes' in analysis_data['data']:
                    stats = analysis_data['data']['attributes'].get('stats', {})
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    
                    if malicious > 2 or (malicious + suspicious) > 3:
                        return 'malicious', malicious + suspicious
                    elif malicious > 0 or suspicious > 0:
                        return 'suspicious', malicious + suspicious
                    else:
                        return 'clean', 0
    
    return 'error', 0

def run_analysis(analysis_id):
    try:
        session = analysis_sessions.get(analysis_id)
        if not session:
            return
        session['status'] = 'processing'
        session['progress_step'] = 1
        email_content = session.get('email_content', '')
        email_data = parse_email_content(email_content)

        session['progress_step'] = 2
        scorer = PhishingScorer()
        risk_score, findings = scorer.calculate_score(email_data)

        session['progress_step'] = 3
        for url in email_data.get('links', []):
            try:
                reputation = get_url_reputation(url)
                if reputation['google_safe_browsing'] == 'malicious':
                    findings.append(f"URL flagged by Google Safe Browsing: {url}")
                    risk_score += 10
                elif reputation['virustotal'] == 'malicious':
                    findings.append(f"URL flagged by VirusTotal: {url}")
                    risk_score += 10
                elif reputation['virustotal'] == 'suspicious':
                    findings.append(f"URL marked as suspicious by VirusTotal: {url}")
                    risk_score += 5
            except Exception as e:
                logger.warning(f"Error checking URL reputation for {url}: {e}")

        risk_score = max(0, min(100, risk_score))

        if risk_score <= 30:
            verdict = 'safe'
        elif risk_score <= 60:
            verdict = 'suspicious'
        else:
            verdict = 'phishing'

        breakdown = {
            'header_spoofing': {'score': 0, 'findings': []},
            'sender_anomalies': {'score': 0, 'findings': []},
            'urgency_language': {'score': 0, 'findings': []},
            'body_red_flags': {'score': 0, 'findings': []},
            'suspicious_links': {'score': 0, 'findings': []},
            'attachments': {'score': 0, 'findings': []}
        }

        for finding in findings:
            finding_lower = finding.lower()
            if any(word in finding_lower for word in ['header', 'spf', 'dkim', 'dmarc', 'reply-to']):
                breakdown['header_spoofing']['findings'].append(finding)
            elif any(word in finding_lower for word in ['sender', 'domain', 'typosquatting', 'free email']):
                breakdown['sender_anomalies']['findings'].append(finding)
            elif any(word in finding_lower for word in ['urgency', 'urgent', 'immediate', 'expire']):
                breakdown['urgency_language']['findings'].append(finding)
            elif any(word in finding_lower for word in ['body', 'greeting', 'credential', 'threat']):
                breakdown['body_red_flags']['findings'].append(finding)
            elif any(word in finding_lower for word in ['url', 'link', 'shortened', 'flagged']):
                breakdown['suspicious_links']['findings'].append(finding)
            elif any(word in finding_lower for word in ['attachment', 'dangerous', 'suspicious']):
                breakdown['attachments']['findings'].append(finding)

        response = {
            'analysis_id': analysis_id,
            'status': 'completed',
            'risk_score': risk_score,
            'verdict': verdict,
            'breakdown': breakdown,
            'extracted_info': {
                'from': email_data.get('from', ''),
                'subject': email_data.get('subject', ''),
                'to': email_data.get('to', ''),
                'links': email_data.get('links', []),
                'attachments': email_data.get('attachments', [])
            }
        }

        session['progress_step'] = 4
        session['result'] = response
        session['status'] = 'completed'
        session['completed_at'] = datetime.now()

    except Exception as e:
        logger.error(f"Async analysis error: {e}")
        if analysis_id in analysis_sessions:
            analysis_sessions[analysis_id]['status'] = 'error'
            analysis_sessions[analysis_id]['error_message'] = 'Analysis failed'

@app.route('/api/analyze/start', methods=['POST'])
def api_analyze_start():
    try:
        data = request.get_json()
        if not data or 'analysis_id' not in data:
            return jsonify({'error': 'analysis_id is required'}), 400
        analysis_id = data['analysis_id']
        session = analysis_sessions.get(analysis_id)
        if not session:
            return jsonify({'error': 'Analysis session not found'}), 404
        if session.get('status') == 'completed':
            return jsonify({'analysis_id': analysis_id, 'status': 'completed'}), 200
        session['status'] = 'processing'
        session['progress_step'] = 1
        t = threading.Thread(target=run_analysis, args=(analysis_id,), daemon=True)
        t.start()
        return jsonify({'analysis_id': analysis_id, 'status': 'processing'}), 202
    except Exception as e:
        logger.error(f"Start analysis error: {e}")
        return jsonify({'error': 'Failed to start analysis'}), 500

@app.route('/api/analyze/status/<analysis_id>')
def api_analyze_status(analysis_id):
    session = analysis_sessions.get(analysis_id)
    if not session:
        return jsonify({'error': 'Analysis session not found'}), 404
    step = session.get('progress_step', 1)
    status = session.get('status', 'processing')
    return jsonify({'analysis_id': analysis_id, 'status': status, 'current_step': step, 'step_key': ANALYSIS_STEPS.get(step, '')})

@app.route('/api/analyze/result/<analysis_id>')
def api_analyze_result(analysis_id):
    session = analysis_sessions.get(analysis_id)
    if not session:
        return jsonify({'error': 'Analysis session not found'}), 404
    if session.get('status') != 'completed':
        return jsonify({'status': session.get('status', 'processing')}), 202
    return jsonify(session.get('result', {}))

@app.route('/')
def index():
    """Homepage with file upload interface"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload"""
    try:
        # Check if file was uploaded
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename and allowed_file(file.filename):
                # Read file content
                email_content = file.read().decode('utf-8', errors='ignore')
                filename = secure_filename(file.filename)
            else:
                flash('Invalid file type. Please upload .eml, .msg, or .txt files.')
                return redirect(url_for('index'))
        
        # Check if text was pasted
        elif 'email_text' in request.form:
            email_content = request.form['email_text']
            filename = 'pasted_email.txt'
            if not email_content.strip():
                flash('Please paste email content or upload a file.')
                return redirect(url_for('index'))
        
        else:
            flash('No file uploaded or text provided.')
            return redirect(url_for('index'))
        
        # Create analysis session
        analysis_id = str(uuid.uuid4())
        
        # Store session
        analysis_sessions[analysis_id] = {
            'id': analysis_id,
            'email_content': email_content,
            'filename': filename,
            'status': 'processing',
            'created_at': datetime.now()
        }
        
        # Redirect to analysis page
        return redirect(url_for('analyze', analysis_id=analysis_id))
        
    except Exception as e:
        logger.error(f"Upload error: {e}")
        flash('Error processing file. Please try again.')
        return redirect(url_for('index'))

@app.route('/analyze/<analysis_id>')
def analyze(analysis_id):
    """Analysis results page"""
    session = analysis_sessions.get(analysis_id)
    if not session:
        flash('Analysis session not found.')
        return redirect(url_for('index'))
    
    return render_template('results.html', analysis_id=analysis_id)

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for email analysis"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request'}), 400
        
        email_content = None
        filename = 'unknown'
        
        analysis_id = data.get('analysis_id')
        if analysis_id:
            session = analysis_sessions.get(analysis_id)
            if not session:
                return jsonify({'error': 'Analysis session not found'}), 404
            email_content = session.get('email_content', '')
            filename = session.get('filename', 'unknown')
        elif 'email_content' in data:
            email_content = data['email_content']
            filename = data.get('filename', 'unknown')
        else:
            return jsonify({'error': 'Email content or analysis_id is required'}), 400
        
        # Parse email
        email_data = parse_email_content(email_content)
        
        # Calculate phishing score
        scorer = PhishingScorer()
        risk_score, findings = scorer.calculate_score(email_data)
        
        # Check URL reputations
        for url in email_data.get('links', []):
            try:
                reputation = get_url_reputation(url)
                # Add URL reputation findings to overall findings
                if reputation['google_safe_browsing'] == 'malicious':
                    findings.append(f"URL flagged by Google Safe Browsing: {url}")
                    risk_score += 10
                elif reputation['virustotal'] == 'malicious':
                    findings.append(f"URL flagged by VirusTotal: {url}")
                    risk_score += 10
                elif reputation['virustotal'] == 'suspicious':
                    findings.append(f"URL marked as suspicious by VirusTotal: {url}")
                    risk_score += 5
            except Exception as e:
                logger.warning(f"Error checking URL reputation for {url}: {e}")
        
        # Ensure score stays within bounds
        risk_score = max(0, min(100, risk_score))
        
        # Determine verdict
        if risk_score <= 30:
            verdict = 'safe'
        elif risk_score <= 60:
            verdict = 'suspicious'
        else:
            verdict = 'phishing'
        
        # Categorize findings
        breakdown = {
            'header_spoofing': {'score': 0, 'findings': []},
            'sender_anomalies': {'score': 0, 'findings': []},
            'urgency_language': {'score': 0, 'findings': []},
            'body_red_flags': {'score': 0, 'findings': []},
            'suspicious_links': {'score': 0, 'findings': []},
            'attachments': {'score': 0, 'findings': []}
        }
        
        # Simple categorization (in production, this would be more sophisticated)
        for finding in findings:
            finding_lower = finding.lower()
            if any(word in finding_lower for word in ['header', 'spf', 'dkim', 'dmarc', 'reply-to']):
                breakdown['header_spoofing']['findings'].append(finding)
            elif any(word in finding_lower for word in ['sender', 'domain', 'typosquatting', 'free email']):
                breakdown['sender_anomalies']['findings'].append(finding)
            elif any(word in finding_lower for word in ['urgency', 'urgent', 'immediate', 'expire']):
                breakdown['urgency_language']['findings'].append(finding)
            elif any(word in finding_lower for word in ['body', 'greeting', 'credential', 'threat']):
                breakdown['body_red_flags']['findings'].append(finding)
            elif any(word in finding_lower for word in ['url', 'link', 'shortened', 'flagged']):
                breakdown['suspicious_links']['findings'].append(finding)
            elif any(word in finding_lower for word in ['attachment', 'dangerous', 'suspicious']):
                breakdown['attachments']['findings'].append(finding)
        
        response = {
            'analysis_id': analysis_id or str(uuid.uuid4()),
            'status': 'completed',
            'risk_score': risk_score,
            'verdict': verdict,
            'breakdown': breakdown,
            'extracted_info': {
                'from': email_data.get('from', ''),
                'subject': email_data.get('subject', ''),
                'to': email_data.get('to', ''),
                'links': email_data.get('links', []),
                'attachments': email_data.get('attachments', [])
            }
        }
        
        if analysis_id:
            analysis_sessions[analysis_id]['status'] = 'completed'
            analysis_sessions[analysis_id]['completed_at'] = datetime.now()
            analysis_sessions[analysis_id]['result'] = response
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"API analysis error: {e}")
        return jsonify({'error': 'Analysis failed'}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    flash('File too large. Maximum size is 10MB.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Clean up old sessions periodically (in production, use proper cleanup)
    def cleanup_sessions():
        current_time = datetime.now()
        expired_sessions = []
        for session_id, session in analysis_sessions.items():
            if current_time - session['created_at'] > timedelta(hours=1):
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del analysis_sessions[session_id]
            logger.info(f"Cleaned up expired session: {session_id}")
    
    # Run cleanup before starting
    cleanup_sessions()
    
    app.run(debug=True, host='0.0.0.0', port=5000)
