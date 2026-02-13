from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import re
from datetime import datetime

import database as db

app = Flask(__name__, static_folder='public')
CORS(app)

db.init_database()

admin_users = {'admin@mans.bank'}

def get_user_from_token(request):
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
        return db.get_user_from_token(token)
    return None

def detect_sql_injection(text):
    if not text:
        return False, []
    
    patterns = [
        r"('\s*OR\s+\d+\s*=\s*\d+)",
        r"('\s*OR\s+'[^']*'\s*=\s*'[^']*')",
        r"(\bUNION\b.*\bSELECT\b)",
        r"(\bDROP\b.*\bTABLE\b)",
        r"(\bINSERT\b.*\bINTO\b)",
        r"(\bDELETE\b.*\bFROM\b)",
        r"(--)",
        r"(#\s*$|#\s+)",
        r"(/\*.*\*/)",
        r"(\bOR\b\s+\d+\s*=\s*\d+)",
        r"(\bAND\b\s+\d+\s*=\s*\d+)",
        r"('\s*;\s*--)",
        r"(\bEXEC\b.*\()",
        r"(\bUPDATE\b.*\bSET\b)",
        r"(\bSELECT\b.*\bFROM\b)",
        r"(\bHAVING\b\s+\d+\s*=)",
        r"('\s*OR\s+1\s*=\s*1)",
        r"(\"\s*OR\s+1\s*=\s*1)",
        r"(;\s*DROP\b)",
        r"(;\s*DELETE\b)",
        r"(;\s*UPDATE\b)",
        r"(;\s*INSERT\b)",
        r"(\bWAITFOR\b.*\bDELAY\b)",
        r"(\bBENCHMARK\b\s*\()",
        r"(\bSLEEP\b\s*\()",
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def detect_xss(text):
    if not text:
        return False, []
    
    patterns = [
        r"<script[^>]*>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"onclick\s*=",
        r"onmouseover\s*=",
        r"<iframe[^>]*>",
        r"<embed[^>]*>",
        r"<object[^>]*>",
        r"eval\s*\(",
        r"alert\s*\(",
        r"confirm\s*\(",
        r"prompt\s*\(",
        r"document\.cookie",
        r"document\.write",
        r"innerHTML\s*=",
        r"<img[^>]*onerror",
        r"<svg[^>]*onload",
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def detect_command_injection(text):
    if not text:
        return False, []
    
    patterns = [
        r";\s*rm\s+-rf",
        r";\s*rm\s+-r",
        r";\s*rm\s+/",
        r";\s*(ls|cat|pwd|whoami|id|uname)",
        r"\|\s*(ls|cat|pwd|whoami|id|uname)",
        r"`[^`]+`",
        r"\$\([^)]+\)",
        r"&&\s*(rm|mv|cp|chmod|chown)",
        r"\|\|\s*(rm|mv|cp|chmod|chown)",
        r">\s*/dev/",
        r"<\s*/etc/",
        r"nc\s+-[elp]",
        r"\bnc\s+.*\d+",
        r"bash\s+-[ci]",
        r"sh\s+-[ci]",
        r"curl\s+.*\|",
        r"wget\s+.*\|",
        r"\bpowershell\b",
        r"\bcmd\.exe\b",
        r"/bin/(sh|bash|zsh|ksh)",
        r";\s*echo\s+",
        r";\s*cat\s+/etc/",
        r"\|.*base64",
        r";\s*python\s+-c",
        r";\s*perl\s+-e",
        r";\s*ruby\s+-e",
        r"\bsudo\s+",
        r"\bchmod\s+[0-7]{3,4}",
        r"\bmkfifo\b",
        r";\s*/",
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def detect_path_traversal(text):
    if not text:
        return False, []
    
    patterns = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e/",
        r"%2e%2e\\",
        r"\.\.%2f",
        r"\.\.%5c",
        r"/etc/passwd",
        r"/etc/shadow",
        r"c:\\windows",
        r"\\windows\\system32",
        r"\.\.;",
        r"%00",
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def detect_ldap_injection(text):
    if not text:
        return False, []
    
    patterns = [
        r"\*\)\(uid=",
        r"\*\)\(cn=",
        r"\*\)\(",
        r"\)\(uid=\*\)\)\(",
        r"\(\|",
        r"\(&",
        r"\(!\(",
        r"\)\(",
        r"\\2a",
        r"\\28",
        r"\\29",
        r"\(\*\)",
        r"uid=\*",
        r"cn=\*",
        r"\|\(.*=\*\)",
        r"&\(.*=\*\)",
        r"\)\)\(.*=",
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def detect_xxe(text):
    if not text:
        return False, []
    
    patterns = [
        r"<!ENTITY\s+\w+\s+SYSTEM",
        r"<!ENTITY\s+%\s*\w+",
        r"<!ENTITY",
        r"<!DOCTYPE[^>]*\[",
        r"<!DOCTYPE.*SYSTEM",
        r"SYSTEM\s+[\"']file:///",
        r"SYSTEM\s+[\"']file://",
        r"SYSTEM\s+[\"']http://",
        r"SYSTEM\s+[\"']https://",
        r"<!ELEMENT",
        r"SYSTEM\s+[\"']php://",
        r"SYSTEM\s+[\"']expect://",
        r"SYSTEM\s+[\"']data://",
        r"SYSTEM\s+[\"']gopher://",
        r"SYSTEM\s+[\"']ftp://",
        r"SYSTEM\s+[\"']/etc/passwd",
        r"PUBLIC\s+[\"']",
        r"<!ATTLIST",
        r"<!NOTATION",
        r"&\w+;.*file:",
        r"%\w+;",
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def detect_nosql_injection(text):
    if not text:
        return False, []
    
    patterns = [
        r'"\$ne"\s*:',
        r"'\$ne'\s*:",
        r"\$ne\s*:",
        r'"\$gt"\s*:',
        r"'\$gt'\s*:",
        r"\$gt\s*:",
        r'"\$lt"\s*:',
        r"\$lt\s*:",
        r'"\$gte"\s*:',
        r"\$gte\s*:",
        r'"\$lte"\s*:',
        r"\$lte\s*:",
        r'"\$regex"\s*:',
        r"\$regex\s*:",
        r'"\$where"\s*:',
        r"\$where\s*:",
        r'"\$exists"\s*:',
        r"\$exists\s*:",
        r'"\$type"\s*:',
        r"\$type\s*:",
        r'"\$or"\s*:',
        r"\$or\s*:",
        r'"\$and"\s*:',
        r"\$and\s*:",
        r'"\$not"\s*:',
        r"\$not\s*:",
        r'"\$in"\s*:',
        r"\$in\s*:",
        r'"\$nin"\s*:',
        r"\$nin\s*:",
        r"{\s*[\"']\$",
        r"\.find\s*\(",
        r"\.findOne\s*\(",
        r"\.remove\s*\(",
        r"\.delete\s*\(",
        r"\.insert\s*\(",
        r"\.update\s*\(",
        r"{\s*\$ne\s*:\s*null\s*}",
        r'{\s*"\$ne"\s*:\s*null\s*}',
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def detect_ssrf(text):
    if not text:
        return False, []
    
    patterns = [
        r"https?://localhost",
        r"https?://127\.0\.0\.1",
        r"https?://0\.0\.0\.0",
        r"https?://\[::1\]",
        r"https?://192\.168\.\d+\.\d+",
        r"https?://10\.\d+\.\d+\.\d+",
        r"https?://172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+",
        r"https?://169\.254\.\d+\.\d+",
        r"file://",
        r"gopher://",
        r"dict://",
        r"ftp://localhost",
        r"tftp://",
        r"ldap://",
        r"@\d+\.\d+\.\d+\.\d+",
        r"https?://[^/]*/admin",
        r"https?://[^/]*/api/",
        r"https?://[^/]*/internal",
        r"https?://metadata\.",
        r"https?://169\.254\.169\.254",
        r"https?://[a-f0-9]+\.burpcollaborator\.",
        r"https?://.*\.internal",
        r"https?://.*\.local",
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def detect_header_injection(text):
    if not text:
        return False, []
    
    patterns = [
        r"\\r\\n.*Set-Cookie",
        r"\\r\\n.*Location:",
        r"\\r\\n",
        r"\\n",
        r"\\r",
        r"%0d%0a",
        r"%0a",
        r"%0d",
        r"\r\nSet-Cookie:",
        r"\r\nLocation:",
        r"\r\nContent-Type:",
        r"\r\nContent-Length:",
        r"\r\nX-",
        r"\nSet-Cookie:",
        r"\nLocation:",
        r"\nContent-Type:",
        r"\nX-Forwarded",
        r"\nHost:",
        r"Set-Cookie:\s*\w+=",
        r"Location:\s*http",
        r"X-Forwarded-For:",
        r"X-Forwarded-Host:",
        r"\r\n\r\n",
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def detect_email_injection(text):
    if not text:
        return False, []
    
    patterns = [
        r"\nbcc:",
        r"\ncc:",
        r"\nto:",
        r"\nfrom:",
        r"\nsubject:",
        r"%0abcc:",
        r"%0acc:",
        r"%0ato:",
        r"\\nbcc:",
        r"\\ncc:",
        r"\\nto:",
        r"Content-Type:.*multipart",
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def detect_file_upload_threats(text):
    if not text:
        return False, []
    
    patterns = [
        r"\.php\d?$",
        r"\.phtml$",
        r"\.jsp$",
        r"\.asp$",
        r"\.aspx$",
        r"\.sh$",
        r"\.bat$",
        r"\.cmd$",
        r"\.exe$",
        r"\.dll$",
        r"\.so$",
        r"\.py$",
        r"\.rb$",
        r"\.pl$",
        r"\.cgi$",
        r"\.htaccess",
        r"\.svg.*<script",
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def check_threat(data):
    threats = []
    
    detectors = [
        ('SQL Injection', detect_sql_injection),
        ('XSS', detect_xss),
        ('Command Injection', detect_command_injection),
        ('Path Traversal', detect_path_traversal),
        ('LDAP Injection', detect_ldap_injection),
        ('XXE', detect_xxe),
        ('NoSQL Injection', detect_nosql_injection),
        ('SSRF', detect_ssrf),
        ('Header Injection', detect_header_injection),
        ('Email Injection', detect_email_injection),
        ('Malicious File Upload', detect_file_upload_threats),
    ]
    
    for key, value in data.items():
        if isinstance(value, str):
            for threat_name, detector_func in detectors:
                is_threat, patterns = detector_func(value)
                if is_threat:
                    threats.append({
                        'type': threat_name,
                        'field': key,
                        'patterns': patterns,
                        'value': value[:100]
                    })
    
    return threats

def analyze_threat_with_ai(threat_data, source='api_request'):
    """Analyze detected threats with Groq AI and create alerts"""
    groq_api_key = os.environ.get('GROQ_API_KEY')
    
    if not groq_api_key:
        return None
    
    text_to_analyze = str(threat_data)
    result = analyze_with_groq(text_to_analyze, groq_api_key)
    
    if result.get('success'):
        analysis = result['analysis']
        if analysis.get('threat_detected'):
            db.add_threat_detection(text_to_analyze, analysis, 'gemini_ai')
            generate_ai_alert_for_threat(analysis, text_to_analyze, source)
            return analysis
    
    return None

def analyze_with_groq(text_to_analyze, groq_api_key):
    try:
        import requests
        import json as json_lib
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {groq_api_key}'
        }
        
        system_prompt = """You are CyberGuardAI, an advanced cybersecurity threat-detection assistant for a learning platform.

Your goal is to analyze security logs, user inputs, code snippets, and data to detect threats, classify them accurately, explain the reasoning, and provide recommended actions. This analysis will be used for students learning cybersecurity.

### CLASSIFICATION RULES:
You MUST output a JSON response with the following format:

{
  "threat_level": "none | low | medium | high | critical",
  "threat_type": "sql_injection | xss | command_injection | path_traversal | ldap_injection | xxe | nosql_injection | ssrf | header_injection | email_injection | file_upload | csrf | brute_force | session_hijacking | recon | malware | auth_bypass | enumeration | privilege_escalation | unknown",
  "description": "A clear, concise explanation of what you detected and why it's dangerous.",
  "evidence": ["list of specific patterns, strings, or indicators that support your conclusion"],
  "recommended_action": "Actionable steps to mitigate this threat.",
  "mitre_technique": "T#### (MITRE ATT&CK technique ID if applicable, else null)"
}

### COMPREHENSIVE DETECTION GUIDANCE:

**Injection Attacks:**
- **SQL Injection**: `' OR 1=1 --`, `UNION SELECT`, `DROP TABLE`, `; DELETE FROM`, `' OR '1'='1`, SQL comments (`--`, `#`, `/**/`)
- **NoSQL Injection**: `$ne`, `$gt`, `$where`, `$regex`, MongoDB operators, JSON-based attacks
- **LDAP Injection**: `*)(`, `|(`, `&(`, special LDAP characters, filter manipulation
- **Command Injection**: Pipe characters (`|`), semicolons (`;`), backticks, `$(command)`, shell commands like `ls`, `cat`, `wget`, `curl`, `nc`, `bash`
- **XXE (XML External Entity)**: `<!ENTITY`, `<!DOCTYPE`, `SYSTEM "file://"`, external entity references

**Cross-Site Attacks:**
- **XSS (Cross-Site Scripting)**: `<script>`, `javascript:`, event handlers (`onerror=`, `onload=`, `onclick=`), `<iframe>`, `<embed>`, `eval()`, `alert()`, `document.cookie`
- **CSRF (Cross-Site Request Forgery)**: Missing CSRF tokens, suspicious form submissions, unauthorized state-changing requests

**Path & File Attacks:**
- **Path Traversal**: `../`, `..\\`, `%2e%2e/`, `/etc/passwd`, `/etc/shadow`, `c:\\windows`, null bytes (`%00`)
- **File Upload Threats**: Executable extensions (`.php`, `.jsp`, `.exe`, `.sh`, `.bat`), double extensions, SVG with scripts

**Network Attacks:**
- **SSRF (Server-Side Request Forgery)**: `localhost`, `127.0.0.1`, `0.0.0.0`, private IP ranges (`192.168.x.x`, `10.x.x.x`), `file://`, `gopher://`, internal network access
- **Header Injection**: CRLF (`\r\n`, `%0d%0a`), header manipulation, response splitting
- **Email Injection**: Newline characters in headers, `\nbcc:`, `\ncc:`, multiple recipients manipulation

**Authentication & Session Attacks:**
- **Brute Force**: Many failed login attempts, rapid password guessing, credential stuffing
- **Session Hijacking**: Stolen session tokens, session fixation, cookie theft
- **Auth Bypass**: Authentication logic flaws, forced browsing, parameter manipulation, JWT attacks

**Reconnaissance & Information Gathering:**
- **Enumeration**: User enumeration, directory bruteforcing, endpoint discovery, timing attacks
- **Reconnaissance**: Port scanning indicators, service fingerprinting, vulnerability scanning patterns
- **Information Disclosure**: Error messages revealing stack traces, version numbers, directory listings

**Advanced Threats:**
- **Privilege Escalation**: Unauthorized access to admin functions, role manipulation, permission bypass
- **Malware**: Suspicious executables, encoded payloads, obfuscated scripts, known malware signatures

### THREAT LEVEL GUIDE:
- **critical**: System compromise imminent, RCE, data exfiltration, complete auth bypass
- **high**: Injection attacks, XSS, path traversal, unauthorized access attempts
- **medium**: Information disclosure, CSRF, header manipulation, reconnaissance
- **low**: Minor configuration issues, suspicious but not clearly malicious
- **none**: Safe input, no threats detected

### STYLE:
- Keep explanations CLEAR and EDUCATIONAL
- Use simple language for students learning security
- Explain WHY something is dangerous, not just WHAT it is
- Provide practical mitigation steps
- Include real-world context when helpful

Now analyze the input and produce your JSON result."""

        payload = {
            'model': 'llama-3.3-70b-versatile',
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': f"### TEXT TO ANALYZE:\n{text_to_analyze}\n\nRespond ONLY with valid JSON. Do not include any markdown formatting or code blocks."}
            ],
            'temperature': 0.1,
            'max_tokens': 1024
        }
        
        key_prefix = groq_api_key[:8] if groq_api_key else "NONE"
        print(f"Using Groq API key starting with: {key_prefix}...")
        
        response = requests.post(
            'https://api.groq.com/openai/v1/chat/completions',
            headers=headers,
            json=payload,
            timeout=30
        )
        
        print(f"Groq API response status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            ai_response = result['choices'][0]['message']['content']
            
            ai_response = re.sub(r'```json\s*', '', ai_response)
            ai_response = re.sub(r'```\s*$', '', ai_response)
            ai_response = ai_response.strip()
            
            ai_analysis = json_lib.loads(ai_response)
            
            threat_detected = ai_analysis.get('threat_level', 'none') != 'none'
            
            return {
                'success': True,
                'analysis': {
                    'threat_detected': threat_detected,
                    'threat_type': ai_analysis.get('threat_type', 'unknown'),
                    'severity': ai_analysis.get('threat_level', 'low'),
                    'patterns': ai_analysis.get('evidence', []),
                    'recommendation': ai_analysis.get('recommended_action', 'Review manually'),
                    'explanation': ai_analysis.get('description', 'Analysis completed'),
                    'mitre_technique': ai_analysis.get('mitre_technique', None)
                }
            }
        else:
            error_msg = f"Groq API returned status {response.status_code}"
            try:
                error_body = response.json()
                if 'error' in error_body:
                    error_msg = error_body['error'].get('message', error_msg)
            except:
                pass
            print(f"Groq API error: {error_msg}")
            return {'success': False, 'error': error_msg}
    except Exception as e:
        print(f"Groq API exception: {e}")
        import traceback
        traceback.print_exc()
        return {'success': False, 'error': str(e)}

def generate_ai_alert_for_threat(analysis, text, source):
    if not analysis.get('threat_detected'):
        return
    
    severity = analysis.get('severity', 'low')
    threat_type = analysis.get('threat_type', 'Unknown')
    
    title_map = {
        'critical': 'CRITICAL THREAT DETECTED',
        'high': 'High Severity Threat Detected',
        'medium': 'Medium Severity Threat Detected',
        'low': 'Low Severity Alert'
    }
    
    title = title_map.get(severity, 'Security Alert')
    
    message = f"{threat_type} attack detected. {analysis.get('explanation', 'Suspicious activity identified.')}"
    
    db.create_ai_alert(
        alert_type=threat_type,
        title=title,
        message=message,
        severity=severity,
        threat_data={
            'text': text[:200],
            'patterns': analysis.get('patterns', []),
            'recommendation': analysis.get('recommendation', ''),
            'source': source
        }
    )

@app.route('/')
def serve_index():
    return send_from_directory('public', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    if os.path.exists(os.path.join('public', path)):
        return send_from_directory('public', path)
    return send_from_directory('public', 'index.html')

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    
    ip_address = request.remote_addr
    
    threats = check_threat(data)
    if threats:
        db.log_security_event(
            'signup_threat',
            f'Threat detected in signup attempt from {ip_address}',
            'high',
            {'threats': threats, 'email': email}
        )
        
        # Trigger AI analysis for all detected threats
        analyze_threat_with_ai(data, source='signup_attempt')
        
        return jsonify({'error': 'Invalid input detected'}), 400
    
    if not email or not password or not name:
        return jsonify({'error': 'Missing required fields'}), 400
    
    if db.get_user(email):
        return jsonify({'error': 'Email already exists'}), 400
    
    if not db.create_user(email, password, name):
        return jsonify({'error': 'Failed to create account'}), 500
    
    token = db.generate_token()
    db.save_token(token, email)
    
    db.log_login_attempt(email, True, ip_address, request.headers.get('User-Agent', ''), 'New signup')
    
    return jsonify({
        'message': 'Account created successfully',
        'token': token,
        'isAdmin': False,
        'user': {
            'email': email,
            'name': name
        }
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    threats = check_threat(data)
    if threats:
        db.log_security_event(
            'login_threat',
            f'Threat detected in login attempt from {ip_address}',
            'high',
            {'threats': threats, 'email': email}
        )
        db.log_login_attempt(email, False, ip_address, user_agent, 'Threat detected')
        
        # Trigger AI analysis for all detected threats
        analyze_threat_with_ai(data, source='login_attempt')
        
        return jsonify({'error': 'Invalid input detected'}), 400
    
    if not email or not password:
        db.log_login_attempt(email or 'unknown', False, ip_address, user_agent, 'Missing credentials')
        return jsonify({'error': 'Missing email or password'}), 400
    
    if db.is_user_blocked(email):
        db.log_login_attempt(email, False, ip_address, user_agent, 'User blocked')
        db.log_security_event(
            'blocked_user_attempt',
            f'Blocked user {email} attempted login from {ip_address}',
            'medium',
            {'email': email, 'ip': ip_address}
        )
        return jsonify({'error': 'Account is blocked. Contact administrator.'}), 403
    
    is_brute_force, attempt_count = db.detect_brute_force(email, ip_address)
    if is_brute_force:
        db.log_security_event(
            'brute_force_detected',
            f'Brute force attempt detected for {email} from {ip_address}',
            'critical',
            {'email': email, 'ip': ip_address, 'attempts': attempt_count}
        )
        
        groq_api_key = os.environ.get('GROQ_API_KEY')
        if groq_api_key:
            db.create_ai_alert(
                alert_type='brute_force',
                title='Brute Force Attack Detected',
                message=f'Multiple failed login attempts ({attempt_count}) detected for {email} from IP {ip_address}. Possible credential stuffing or brute force attack.',
                severity='critical',
                threat_data={
                    'email': email,
                    'ip_address': ip_address,
                    'attempt_count': attempt_count,
                    'recommendation': 'Consider blocking this IP address and notifying the user.'
                }
            )
    
    if not db.verify_password(email, password):
        db.log_login_attempt(email, False, ip_address, user_agent, 'Invalid credentials')
        return jsonify({'error': 'Invalid email or password'}), 401
    
    user = db.get_user(email)
    token = db.generate_token()
    db.save_token(token, email)
    
    db.log_login_attempt(email, True, ip_address, user_agent, 'Successful login')
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'isAdmin': user.get('is_admin', False),
        'user': {
            'email': user['email'],
            'name': user['name']
        }
    }), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
        db.remove_token(token)
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/account', methods=['GET'])
def get_account():
    user_email = get_user_from_token(request)
    
    if not user_email:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = db.get_user(user_email)
    account = db.get_account(user_email)
    
    if not user or not account:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'user': {
            'email': user['email'],
            'name': user['name'],
            'isAdmin': user.get('is_admin', False)
        },
        'account': account
    }), 200

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    user_email = get_user_from_token(request)
    
    if not user_email:
        return jsonify({'authenticated': False}), 200
    
    user = db.get_user(user_email)
    if not user:
        return jsonify({'authenticated': False}), 200
    
    return jsonify({
        'authenticated': True,
        'user': {
            'email': user['email'],
            'name': user['name'],
            'isAdmin': user.get('is_admin', False)
        }
    }), 200

@app.route('/api/admin/users', methods=['GET'])
def get_all_users():
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    users = db.get_all_users()
    return jsonify({'users': users}), 200

@app.route('/api/admin/add-funds', methods=['POST'])
def add_funds():
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    target_email = data.get('email')
    amount = data.get('amount')
    
    if not target_email or amount is None or amount == 0:
        return jsonify({'error': 'Invalid request'}), 400
    
    if not db.get_user(target_email):
        return jsonify({'error': 'User not found'}), 404
    
    account = db.get_account(target_email)
    if not account:
        return jsonify({'error': 'User account not found'}), 404
    
    if amount < 0 and account['balance'] + amount < 0:
        return jsonify({'error': 'Insufficient balance to reduce by this amount'}), 400
    
    new_balance = db.add_funds(target_email, amount)
    
    action = 'added' if amount > 0 else 'reduced'
    abs_amount = abs(amount)
    
    db.log_security_event(
        'admin_adjust_funds',
        f'Admin {action} ${abs_amount} {"to" if amount > 0 else "from"} {target_email}',
        'low',
        {'admin': user_email, 'target': target_email, 'amount': amount, 'action': action}
    )
    
    return jsonify({
        'message': f'Funds {action} successfully',
        'new_balance': new_balance,
        'amount': amount
    }), 200

@app.route('/api/admin/block-user', methods=['POST'])
def block_user():
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    target_email = data.get('email')
    blocked = data.get('blocked', True)
    
    if not target_email:
        return jsonify({'error': 'Invalid request'}), 400
    
    if not db.get_user(target_email):
        return jsonify({'error': 'User not found'}), 404
    
    if db.is_user_admin(target_email):
        return jsonify({'error': 'Cannot block admin users'}), 400
    
    db.block_user(target_email, blocked)
    
    message = f'User {target_email} has been {"blocked" if blocked else "unblocked"}'
    
    db.log_security_event(
        'admin_block_user',
        message,
        'medium',
        {'admin': user_email, 'target': target_email, 'blocked': blocked}
    )
    
    return jsonify({'message': message}), 200

@app.route('/api/admin/delete-user', methods=['DELETE'])
def delete_user():
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    target_email = data.get('email')
    
    if not target_email:
        return jsonify({'error': 'Invalid request'}), 400
    
    if not db.get_user(target_email):
        return jsonify({'error': 'User not found'}), 404
    
    if db.is_user_admin(target_email):
        return jsonify({'error': 'Cannot delete admin users'}), 400
    
    db.delete_user(target_email)
    
    db.log_security_event(
        'admin_delete_user',
        f'Admin deleted user {target_email}',
        'high',
        {'admin': user_email, 'target': target_email}
    )
    
    return jsonify({'message': f'User {target_email} has been deleted'}), 200

@app.route('/api/admin/security-logs', methods=['GET'])
def get_security_logs():
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    log_type = request.args.get('type', 'all')
    limit = int(request.args.get('limit', 100))
    
    if log_type == 'login':
        logs = db.get_login_logs(limit)
        return jsonify({'logs': logs}), 200
    elif log_type == 'security':
        logs = db.get_security_events(limit)
        return jsonify({'logs': logs}), 200
    else:
        return jsonify({
            'login_logs': db.get_login_logs(limit),
            'security_events': db.get_security_events(limit)
        }), 200

@app.route('/api/admin/security-stats', methods=['GET'])
def get_security_stats():
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify(db.get_security_stats()), 200

@app.route('/api/admin/cyberguard/analyze', methods=['POST'])
def cyberguard_analyze():
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    text_to_analyze = data.get('text', '')
    
    if not text_to_analyze:
        return jsonify({'error': 'No text provided'}), 400
    
    print(f"Analyzing text: {text_to_analyze[:100]}...")
    
    groq_api_key = os.environ.get('GROQ_API_KEY')
    ai_analysis_attempted = False
    ai_analysis_success = False
    
    if groq_api_key:
        print("Groq API key found, attempting AI analysis...")
        ai_analysis_attempted = True
        result = analyze_with_groq(text_to_analyze, groq_api_key)
        
        if result.get('success'):
            ai_analysis_success = True
            analysis = result['analysis']
            print(f"AI Analysis result: threat_detected={analysis.get('threat_detected')}, type={analysis.get('threat_type')}")
            
            if analysis.get('threat_detected'):
                db.add_threat_detection(text_to_analyze, analysis, 'groq_ai')
                generate_ai_alert_for_threat(analysis, text_to_analyze, 'manual_analysis')
                print(f"AI Alert generated for threat: {analysis.get('threat_type')}")
            
            return jsonify({
                'analyzed': True,
                'source': 'groq_ai',
                'analysis': analysis
            }), 200
        else:
            print(f"Groq AI analysis failed: {result.get('error')}, falling back to local detection")
    else:
        print("No Groq API key, using local detection only")
    
    print("Running local threat detection...")
    detectors = [
        ('SQL Injection', detect_sql_injection, 'high'),
        ('XSS', detect_xss, 'high'),
        ('Command Injection', detect_command_injection, 'critical'),
        ('Path Traversal', detect_path_traversal, 'high'),
        ('LDAP Injection', detect_ldap_injection, 'high'),
        ('XXE', detect_xxe, 'critical'),
        ('NoSQL Injection', detect_nosql_injection, 'high'),
        ('SSRF', detect_ssrf, 'critical'),
        ('Header Injection', detect_header_injection, 'medium'),
        ('Email Injection', detect_email_injection, 'medium'),
        ('Malicious File Upload', detect_file_upload_threats, 'high'),
    ]
    
    detected_threats = []
    all_patterns = []
    
    for threat_name, detector_func, severity in detectors:
        is_threat, patterns = detector_func(text_to_analyze)
        if is_threat:
            detected_threats.append({
                'type': threat_name,
                'severity': severity,
                'patterns': patterns
            })
            all_patterns.extend(patterns)
    
    if detected_threats:
        print(f"Local detection found {len(detected_threats)} threat type(s)")
        primary_threat = max(detected_threats, key=lambda x: 
            {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x['severity'], 0))
        
        analysis = {
            'threat_detected': True,
            'threat_type': primary_threat['type'],
            'severity': primary_threat['severity'],
            'patterns': all_patterns[:10],
            'recommendation': f"Block and investigate - {len(detected_threats)} threat type(s) detected",
            'explanation': f"Security threats detected: {', '.join([t['type'] for t in detected_threats])}"
        }
        
        print(f"Saving threat detection to database...")
        db.add_threat_detection(text_to_analyze, analysis, 'local_detection')
        print(f"Generating alert for: {primary_threat['type']}")
        generate_ai_alert_for_threat(analysis, text_to_analyze, 'manual_analysis')
        print(f"Alert generated successfully")
    else:
        print("No threats detected by local analysis")
        analysis = {
            'threat_detected': False,
            'threat_type': 'None',
            'severity': 'low',
            'patterns': [],
            'recommendation': 'Safe to proceed',
            'explanation': 'No threats detected by local analysis'
        }
    
    return jsonify({
        'analyzed': True,
        'source': 'local_detection',
        'analysis': analysis
    }), 200

@app.route('/api/admin/cyberguard/threats', methods=['GET'])
def get_threat_detections():
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    limit = int(request.args.get('limit', 50))
    
    threats = db.get_threat_detections(limit)
    
    return jsonify({'threats': threats}), 200

@app.route('/api/admin/cyberguard/status', methods=['GET'])
def get_cyberguard_status():
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    groq_api_key = os.environ.get('GROQ_API_KEY')
    stats = db.get_security_stats()
    
    status = {
        'ai_enabled': bool(groq_api_key),
        'local_detection_enabled': True,
        'total_threats_detected': stats['total_threats_detected'],
        'protection_active': True
    }
    
    return jsonify(status), 200

@app.route('/api/admin/alerts', methods=['GET'])
def get_alerts():
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    limit = int(request.args.get('limit', 50))
    unread_only = request.args.get('unread_only', 'false').lower() == 'true'
    
    alerts = db.get_ai_alerts(limit, unread_only)
    unread_count = db.get_unread_alert_count()
    
    return jsonify({
        'alerts': alerts,
        'unread_count': unread_count
    }), 200

@app.route('/api/admin/alerts/<int:alert_id>/read', methods=['POST'])
def mark_alert_as_read(alert_id):
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    db.mark_alert_read(alert_id)
    
    return jsonify({'message': 'Alert marked as read'}), 200

@app.route('/api/admin/alerts/<int:alert_id>/dismiss', methods=['POST'])
def dismiss_alert(alert_id):
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    db.dismiss_alert(alert_id)
    
    return jsonify({'message': 'Alert dismissed'}), 200

@app.route('/api/admin/alerts/count', methods=['GET'])
def get_alert_count():
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    count = db.get_unread_alert_count()
    
    return jsonify({'unread_count': count}), 200

@app.route('/api/admin/alerts/<int:alert_id>/analyze', methods=['POST'])
def analyze_alert_with_ai(alert_id):
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    groq_api_key = os.environ.get('GROQ_API_KEY')
    
    if not groq_api_key:
        return jsonify({'error': 'AI is not configured. Please add GROQ_API_KEY.'}), 400
    
    alert = db.get_alert_by_id(alert_id)
    
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
    text_to_analyze = ""
    if alert.get('threat_data'):
        threat_data = alert['threat_data']
        if isinstance(threat_data, dict):
            text_to_analyze = threat_data.get('text', '')
            if threat_data.get('patterns'):
                text_to_analyze += f"\nPatterns: {', '.join(str(p) for p in threat_data.get('patterns', []))}"
        else:
            text_to_analyze = str(threat_data)
    
    if not text_to_analyze:
        text_to_analyze = f"{alert.get('title', '')} - {alert.get('message', '')}"
    
    result = analyze_with_groq(text_to_analyze, groq_api_key)
    
    if result.get('success'):
        analysis = result['analysis']
        db.update_alert_analysis(alert_id, analysis)
        
        return jsonify({
            'success': True,
            'alert_id': alert_id,
            'analysis': analysis
        }), 200
    else:
        return jsonify({
            'success': False,
            'error': result.get('error', 'Analysis failed')
        }), 500

@app.route('/api/admin/database/stats', methods=['GET'])
def get_database_stats_route():
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    stats = db.get_database_stats()
    
    return jsonify(stats), 200

@app.route('/api/admin/database/table/<table_name>', methods=['GET'])
def get_table_data_route(table_name):
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    allowed_tables = ['login_logs', 'security_events', 'threat_detections', 'ai_alerts']
    
    if table_name not in allowed_tables:
        return jsonify({'error': 'Invalid table name'}), 400
    
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    
    data = db.get_table_data(table_name, limit, offset)
    
    return jsonify({
        'table': table_name,
        'data': data,
        'limit': limit,
        'offset': offset
    }), 200

@app.route('/api/admin/database/clear/<table_name>', methods=['DELETE'])
def clear_table_data_route(table_name):
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    clearable_tables = ['login_logs', 'security_events', 'threat_detections', 'ai_alerts']
    
    if table_name not in clearable_tables:
        return jsonify({'error': 'Cannot clear this table. Only log and alert tables can be cleared.'}), 400
    
    success, message = db.clear_table_data(table_name)
    
    if success:
        db.log_security_event(
            'admin_clear_table',
            f'Admin {user_email} cleared table {table_name}',
            'medium',
            {'table': table_name, 'admin': user_email}
        )
        return jsonify({'success': True, 'message': message}), 200
    else:
        return jsonify({'success': False, 'error': message}), 400

@app.route('/api/admin/database/clear-old', methods=['DELETE', 'POST'])
def clear_old_logs_route():
    user_email = get_user_from_token(request)
    
    if not user_email or not db.is_user_admin(user_email):
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json or {}
    days = int(data.get('days', 30))
    print(f"Clearing logs older than {days} days")
    
    if days < 1:
        return jsonify({'error': 'Days must be at least 1'}), 400
    
    cleared = db.clear_old_logs(days)
    
    total_cleared = sum(cleared.values())
    
    if total_cleared > 0:
        db.log_security_event(
            'admin_clear_old_logs',
            f'Admin {user_email} cleared logs older than {days} days',
            'low',
            {'days': days, 'cleared': cleared, 'admin': user_email}
        )
    
    return jsonify({
        'success': True,
        'days': days,
        'cleared': cleared,
        'total_cleared': total_cleared
    }), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
