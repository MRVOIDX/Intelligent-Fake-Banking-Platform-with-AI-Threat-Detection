from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
import secrets
from datetime import datetime
import re

app = Flask(__name__, static_folder='public')
CORS(app)

# In-memory storage
users = {}
user_accounts = {}
blocked_users = set()
login_logs = []
security_events = []
threat_detections = []
active_tokens = {}  # Token-based authentication

# Admin tracking
admin_users = {'admin@mans.bank'}

# Default admin user
users['admin@mans.bank'] = {
    'email': 'admin@mans.bank',
    'password': generate_password_hash('admin123'),
    'name': 'Admin User',
    'isAdmin': True
}
user_accounts['admin@mans.bank'] = {
    'balance': 12450.87,
    'available': 10200.00,
    'savings': 2250.87,
    'card_number': '4825',
    'transactions': [
        {'type': 'sent', 'amount': -150.00, 'to': 'John Doe', 'time': '2 mins'},
        {'type': 'received', 'amount': 500.00, 'from': 'Salary', 'time': '45 mins'},
        {'type': 'purchase', 'amount': -45.99, 'at': 'Coffee Shop', 'time': '1 hour'},
    ]
}

def generate_token():
    """Generate a secure random token"""
    return secrets.token_hex(32)

def get_user_from_token(request):
    """Extract user email from Bearer token"""
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
        return active_tokens.get(token)
    return None

def log_login_attempt(email, success, ip_address, user_agent='', reason=''):
    """Log all login attempts"""
    login_logs.append({
        'timestamp': datetime.now().isoformat(),
        'email': email,
        'success': success,
        'ip_address': ip_address,
        'user_agent': user_agent,
        'reason': reason
    })
    
    if len(login_logs) > 1000:
        login_logs.pop(0)

def log_security_event(event_type, description, severity, data=None):
    """Log security events for monitoring"""
    security_events.append({
        'timestamp': datetime.now().isoformat(),
        'type': event_type,
        'description': description,
        'severity': severity,
        'data': data or {}
    })
    
    if len(security_events) > 500:
        security_events.pop(0)

def detect_brute_force(email, ip_address):
    """Detect brute force attempts"""
    recent_failures = [
        log for log in login_logs[-50:]
        if not log['success'] and (log['email'] == email or log['ip_address'] == ip_address)
    ]
    
    if len(recent_failures) >= 5:
        return True, len(recent_failures)
    return False, len(recent_failures)

def detect_sql_injection(text):
    """SQL injection detection"""
    if not text:
        return False, []
    
    patterns = [
        r"(\bUNION\b.*\bSELECT\b)",
        r"(\bDROP\b.*\bTABLE\b)",
        r"(\bINSERT\b.*\bINTO\b)",
        r"(\bDELETE\b.*\bFROM\b)",
        r"(--|\#|\/\*)",
        r"(\bOR\b.*=.*)",
        r"(\bAND\b.*=.*)",
        r"('.*\bOR\b.*'=')",
        r"(\bEXEC\b.*\()",
        r"(\bUPDATE\b.*\bSET\b)",
        r"(\bSELECT\b.*\bFROM\b)",
        r"(';.*--)",
        r"(\bHAVING\b.*=)",
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def detect_xss(text):
    """Cross-Site Scripting (XSS) detection"""
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
    """Command injection detection"""
    if not text:
        return False, []
    
    patterns = [
        r";\s*(ls|cat|pwd|whoami|id|uname)",
        r"\|\s*(ls|cat|pwd|whoami|id|uname)",
        r"`.*`",
        r"\$\(.*\)",
        r"&&\s*(rm|mv|cp|chmod)",
        r"\|\|\s*(rm|mv|cp|chmod)",
        r">\s*/dev/",
        r"<\s*/etc/",
        r"nc\s+-",
        r"bash\s+-",
        r"sh\s+-",
        r"curl\s+",
        r"wget\s+",
        r"powershell",
        r"cmd\.exe",
        r"/bin/",
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def detect_path_traversal(text):
    """Path traversal detection"""
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
    """LDAP injection detection"""
    if not text:
        return False, []
    
    patterns = [
        r"\*\)",
        r"\(\|",
        r"\(&",
        r"\(!\(",
        r"\)\(",
        r"\\2a",
        r"\\28",
        r"\\29",
        r"\|\|",
        r"&&",
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def detect_xxe(text):
    """XML External Entity (XXE) detection"""
    if not text:
        return False, []
    
    patterns = [
        r"<!ENTITY",
        r"<!DOCTYPE",
        r"SYSTEM\s+[\"']file://",
        r"SYSTEM\s+[\"']http://",
        r"SYSTEM\s+[\"']https://",
        r"<!ELEMENT",
        r"SYSTEM\s+[\"']php://",
        r"SYSTEM\s+[\"']expect://",
        r"SYSTEM\s+[\"']data://",
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def detect_nosql_injection(text):
    """NoSQL injection detection"""
    if not text:
        return False, []
    
    patterns = [
        r"\$ne:",
        r"\$gt:",
        r"\$lt:",
        r"\$gte:",
        r"\$lte:",
        r"\$regex:",
        r"\$where:",
        r"\$exists:",
        r"\$type:",
        r"\$or:",
        r"\$and:",
        r"\$not:",
        r"{\s*\$",
        r"\.find\s*\(",
        r"\.remove\s*\(",
        r"\.insert\s*\(",
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def detect_ssrf(text):
    """Server-Side Request Forgery (SSRF) detection"""
    if not text:
        return False, []
    
    patterns = [
        r"localhost",
        r"127\.0\.0\.1",
        r"0\.0\.0\.0",
        r"192\.168\.",
        r"10\.\d+\.\d+\.\d+",
        r"172\.(1[6-9]|2\d|3[0-1])\.",
        r"file://",
        r"gopher://",
        r"dict://",
        r"ftp://",
        r"tftp://",
        r"ldap://",
        r"@\d+\.\d+\.\d+\.\d+",
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def detect_header_injection(text):
    """HTTP Header injection detection"""
    if not text:
        return False, []
    
    patterns = [
        r"\\r\\n",
        r"\\n",
        r"\\r",
        r"%0d%0a",
        r"%0a",
        r"%0d",
        r"\n\r",
        r"\r\n",
        r"Set-Cookie:",
        r"Location:",
        r"Content-Type:",
        r"Content-Length:",
    ]
    
    detected = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
    
    return len(detected) > 0, detected

def detect_email_injection(text):
    """Email injection detection"""
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
    """Malicious file upload detection"""
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
    """Check for various threats in incoming data"""
    threats = []
    
    # List of all detection functions with their names
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
            # Check all threat types
            for threat_name, detector_func in detectors:
                is_threat, patterns = detector_func(value)
                if is_threat:
                    threats.append({
                        'type': threat_name,
                        'field': key,
                        'patterns': patterns,
                        'value': value[:100]  # Truncate for safety
                    })
    
    return threats

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
        log_security_event(
            'signup_threat',
            f'Threat detected in signup attempt from {ip_address}',
            'high',
            {'threats': threats, 'email': email}
        )
        return jsonify({'error': 'Invalid input detected'}), 400
    
    if not email or not password or not name:
        return jsonify({'error': 'Missing required fields'}), 400
    
    if email in users:
        return jsonify({'error': 'Email already exists'}), 400
    
    users[email] = {
        'email': email,
        'password': generate_password_hash(password),
        'name': name,
        'isAdmin': False
    }
    
    user_accounts[email] = {
        'balance': 1000.00,
        'available': 1000.00,
        'savings': 0.00,
        'card_number': str(secrets.randbelow(9000) + 1000),
        'transactions': [
            {'type': 'received', 'amount': 1000.00, 'from': 'Welcome Bonus', 'time': 'Just now'},
        ]
    }
    
    token = generate_token()
    active_tokens[token] = email
    
    log_login_attempt(email, True, ip_address, request.headers.get('User-Agent', ''), 'New signup')
    
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
        log_security_event(
            'login_threat',
            f'Threat detected in login attempt from {ip_address}',
            'high',
            {'threats': threats, 'email': email}
        )
        log_login_attempt(email, False, ip_address, user_agent, 'Threat detected')
        return jsonify({'error': 'Invalid input detected'}), 400
    
    if not email or not password:
        log_login_attempt(email or 'unknown', False, ip_address, user_agent, 'Missing credentials')
        return jsonify({'error': 'Missing email or password'}), 400
    
    if email in blocked_users:
        log_login_attempt(email, False, ip_address, user_agent, 'User blocked')
        log_security_event(
            'blocked_user_attempt',
            f'Blocked user {email} attempted login from {ip_address}',
            'medium',
            {'email': email, 'ip': ip_address}
        )
        return jsonify({'error': 'Account is blocked. Contact administrator.'}), 403
    
    is_brute_force, attempt_count = detect_brute_force(email, ip_address)
    if is_brute_force:
        log_security_event(
            'brute_force_detected',
            f'Brute force attempt detected for {email} from {ip_address}',
            'critical',
            {'email': email, 'ip': ip_address, 'attempts': attempt_count}
        )
    
    user = users.get(email)
    if not user or not check_password_hash(user['password'], password):
        log_login_attempt(email, False, ip_address, user_agent, 'Invalid credentials')
        return jsonify({'error': 'Invalid email or password'}), 401
    
    token = generate_token()
    active_tokens[token] = email
    
    log_login_attempt(email, True, ip_address, user_agent, 'Successful login')
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'isAdmin': user.get('isAdmin', False),
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
        active_tokens.pop(token, None)
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/account', methods=['GET'])
def get_account():
    user_email = get_user_from_token(request)
    
    if not user_email:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = users.get(user_email)
    account = user_accounts.get(user_email)
    
    if not user or not account:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'user': {
            'email': user['email'],
            'name': user['name'],
            'isAdmin': user.get('isAdmin', False)
        },
        'account': account
    }), 200

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    user_email = get_user_from_token(request)
    
    if not user_email:
        return jsonify({'authenticated': False}), 200
    
    user = users.get(user_email)
    if not user:
        return jsonify({'authenticated': False}), 200
    
    return jsonify({
        'authenticated': True,
        'user': {
            'email': user['email'],
            'name': user['name'],
            'isAdmin': user.get('isAdmin', False)
        }
    }), 200

# Admin endpoints
@app.route('/api/admin/users', methods=['GET'])
def get_all_users():
    user_email = get_user_from_token(request)
    
    if not user_email or user_email not in admin_users:
        return jsonify({'error': 'Unauthorized'}), 403
    
    user_list = []
    for email, user in users.items():
        account = user_accounts.get(email)
        user_list.append({
            'email': email,
            'name': user['name'],
            'isAdmin': user.get('isAdmin', False),
            'blocked': email in blocked_users,
            'account': account
        })
    
    return jsonify({'users': user_list}), 200

@app.route('/api/admin/add-funds', methods=['POST'])
def add_funds():
    user_email = get_user_from_token(request)
    
    if not user_email or user_email not in admin_users:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    target_email = data.get('email')
    amount = data.get('amount')
    
    if not target_email or not amount or amount <= 0:
        return jsonify({'error': 'Invalid request'}), 400
    
    if target_email not in user_accounts:
        return jsonify({'error': 'User not found'}), 404
    
    user_accounts[target_email]['balance'] += amount
    user_accounts[target_email]['available'] += amount
    
    user_accounts[target_email]['transactions'].insert(0, {
        'type': 'received',
        'amount': amount,
        'from': 'Admin Credit',
        'time': 'Just now'
    })
    
    log_security_event(
        'admin_add_funds',
        f'Admin added ${amount} to {target_email}',
        'low',
        {'admin': user_email, 'target': target_email, 'amount': amount}
    )
    
    return jsonify({'message': 'Funds added successfully', 'new_balance': user_accounts[target_email]['balance']}), 200

@app.route('/api/admin/block-user', methods=['POST'])
def block_user():
    user_email = get_user_from_token(request)
    
    if not user_email or user_email not in admin_users:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    target_email = data.get('email')
    blocked = data.get('blocked', True)
    
    if not target_email:
        return jsonify({'error': 'Invalid request'}), 400
    
    if target_email not in users:
        return jsonify({'error': 'User not found'}), 404
    
    if target_email in admin_users:
        return jsonify({'error': 'Cannot block admin users'}), 400
    
    if blocked:
        blocked_users.add(target_email)
        # Remove active tokens
        tokens_to_remove = [token for token, email in active_tokens.items() if email == target_email]
        for token in tokens_to_remove:
            active_tokens.pop(token, None)
        message = f'User {target_email} has been blocked'
    else:
        blocked_users.discard(target_email)
        message = f'User {target_email} has been unblocked'
    
    log_security_event(
        'admin_block_user',
        message,
        'medium',
        {'admin': user_email, 'target': target_email, 'blocked': blocked}
    )
    
    return jsonify({'message': message}), 200

@app.route('/api/admin/delete-user', methods=['DELETE'])
def delete_user():
    user_email = get_user_from_token(request)
    
    if not user_email or user_email not in admin_users:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    target_email = data.get('email')
    
    if not target_email:
        return jsonify({'error': 'Invalid request'}), 400
    
    if target_email not in users:
        return jsonify({'error': 'User not found'}), 404
    
    if target_email in admin_users:
        return jsonify({'error': 'Cannot delete admin users'}), 400
    
    users.pop(target_email, None)
    user_accounts.pop(target_email, None)
    blocked_users.discard(target_email)
    
    # Remove active tokens
    tokens_to_remove = [token for token, email in active_tokens.items() if email == target_email]
    for token in tokens_to_remove:
        active_tokens.pop(token, None)
    
    log_security_event(
        'admin_delete_user',
        f'Admin deleted user {target_email}',
        'high',
        {'admin': user_email, 'target': target_email}
    )
    
    return jsonify({'message': f'User {target_email} has been deleted'}), 200

@app.route('/api/admin/security-logs', methods=['GET'])
def get_security_logs():
    user_email = get_user_from_token(request)
    
    if not user_email or user_email not in admin_users:
        return jsonify({'error': 'Unauthorized'}), 403
    
    log_type = request.args.get('type', 'all')
    limit = int(request.args.get('limit', 100))
    
    if log_type == 'login':
        logs = sorted(login_logs, key=lambda x: x['timestamp'], reverse=True)[:limit]
        return jsonify({'logs': logs}), 200
    elif log_type == 'security':
        logs = sorted(security_events, key=lambda x: x['timestamp'], reverse=True)[:limit]
        return jsonify({'logs': logs}), 200
    else:
        return jsonify({
            'login_logs': sorted(login_logs, key=lambda x: x['timestamp'], reverse=True)[:limit],
            'security_events': sorted(security_events, key=lambda x: x['timestamp'], reverse=True)[:limit]
        }), 200

@app.route('/api/admin/security-stats', methods=['GET'])
def get_security_stats():
    user_email = get_user_from_token(request)
    
    if not user_email or user_email not in admin_users:
        return jsonify({'error': 'Unauthorized'}), 403
    
    total_logins = len(login_logs)
    failed_logins = len([log for log in login_logs if not log['success']])
    successful_logins = len([log for log in login_logs if log['success']])
    brute_force_events = len([event for event in security_events if event['type'] == 'brute_force_detected'])
    sql_injection_events = len([event for event in security_events if 'threat' in event['type']])
    critical_events = len([event for event in security_events if event['severity'] == 'critical'])
    high_events = len([event for event in security_events if event['severity'] == 'high'])
    
    return jsonify({
        'total_logins': total_logins,
        'failed_logins': failed_logins,
        'successful_logins': successful_logins,
        'brute_force_attempts': brute_force_events,
        'sql_injection_attempts': sql_injection_events,
        'critical_events': critical_events,
        'high_severity_events': high_events,
        'blocked_users_count': len(blocked_users)
    }), 200

@app.route('/api/admin/cyberguard/analyze', methods=['POST'])
def cyberguard_analyze():
    user_email = get_user_from_token(request)
    
    if not user_email or user_email not in admin_users:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    text_to_analyze = data.get('text', '')
    
    if not text_to_analyze:
        return jsonify({'error': 'No text provided'}), 400
    
    gemini_api_key = os.environ.get('GEMINI_API_KEY')
    
    if gemini_api_key:
        try:
            import requests
            import re
            
            headers = {'Content-Type': 'application/json'}
            
            # CyberGuardAI System Prompt - Enhanced with more threat types
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
                'contents': [{
                    'parts': [{
                        'text': f"""{system_prompt}

### TEXT TO ANALYZE:
{text_to_analyze}

Respond ONLY with valid JSON. Do not include any markdown formatting or code blocks."""
                    }]
                }]
            }
            
            response = requests.post(
                f'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={gemini_api_key}',
                headers=headers,
                json=payload,
                timeout=15
            )
            
            if response.status_code == 200:
                result = response.json()
                ai_response = result['candidates'][0]['content']['parts'][0]['text']
                
                # Clean up the response - remove markdown code blocks if present
                ai_response = re.sub(r'```json\s*', '', ai_response)
                ai_response = re.sub(r'```\s*$', '', ai_response)
                ai_response = ai_response.strip()
                
                try:
                    import json as json_lib
                    ai_analysis = json_lib.loads(ai_response)
                    
                    # Convert to our internal format
                    threat_detected = ai_analysis.get('threat_level', 'none') != 'none'
                    
                    analysis = {
                        'threat_detected': threat_detected,
                        'threat_type': ai_analysis.get('threat_type', 'unknown'),
                        'severity': ai_analysis.get('threat_level', 'low'),
                        'patterns': ai_analysis.get('evidence', []),
                        'recommendation': ai_analysis.get('recommended_action', 'Review manually'),
                        'explanation': ai_analysis.get('description', 'Analysis completed'),
                        'mitre_technique': ai_analysis.get('mitre_technique', None)
                    }
                    
                except Exception as parse_error:
                    print(f"JSON parse error: {parse_error}, Response: {ai_response}")
                    analysis = {
                        'threat_detected': False,
                        'threat_type': 'Analysis Error',
                        'severity': 'low',
                        'patterns': [],
                        'recommendation': 'Manual review recommended - AI response format error',
                        'explanation': f'Could not parse AI response. Raw output: {ai_response[:200]}'
                    }
                
                if analysis.get('threat_detected'):
                    threat_detections.append({
                        'timestamp': datetime.now().isoformat(),
                        'text': text_to_analyze[:200],
                        'analysis': analysis,
                        'source': 'gemini_ai'
                    })
                
                return jsonify({
                    'analyzed': True,
                    'source': 'gemini_ai',
                    'analysis': analysis
                }), 200
                
        except Exception as e:
            print(f"Gemini API error: {e}")
            import traceback
            traceback.print_exc()
            pass
    
    # Fallback to local detection - check all threat types
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
        # Use the highest severity threat
        primary_threat = max(detected_threats, key=lambda x: 
            {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x['severity'], 0))
        
        analysis = {
            'threat_detected': True,
            'threat_type': primary_threat['type'],
            'severity': primary_threat['severity'],
            'patterns': all_patterns[:10],  # Limit patterns for display
            'recommendation': f"Block and investigate - {len(detected_threats)} threat type(s) detected",
            'explanation': f"Multiple security threats detected: {', '.join([t['type'] for t in detected_threats])}"
        }
    else:
        analysis = {
            'threat_detected': False,
            'threat_type': 'None',
            'severity': 'low',
            'patterns': [],
            'recommendation': 'Safe to proceed',
            'explanation': 'No threats detected by local analysis'
        }
    
    if detected_threats:
        threat_detections.append({
            'timestamp': datetime.now().isoformat(),
            'text': text_to_analyze[:200],
            'analysis': analysis,
            'source': 'local_detection'
        })
    
    return jsonify({
        'analyzed': True,
        'source': 'local_detection',
        'analysis': analysis
    }), 200

@app.route('/api/admin/cyberguard/threats', methods=['GET'])
def get_threat_detections():
    user_email = get_user_from_token(request)
    
    if not user_email or user_email not in admin_users:
        return jsonify({'error': 'Unauthorized'}), 403
    
    limit = int(request.args.get('limit', 50))
    
    threats = sorted(threat_detections, key=lambda x: x['timestamp'], reverse=True)[:limit]
    
    return jsonify({'threats': threats}), 200

@app.route('/api/admin/cyberguard/status', methods=['GET'])
def get_cyberguard_status():
    user_email = get_user_from_token(request)
    
    if not user_email or user_email not in admin_users:
        return jsonify({'error': 'Unauthorized'}), 403
    
    gemini_api_key = os.environ.get('GEMINI_API_KEY')
    
    status = {
        'gemini_enabled': bool(gemini_api_key),
        'local_detection_enabled': True,
        'total_threats_detected': len(threat_detections),
        'protection_active': True
    }
    
    return jsonify(status), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
