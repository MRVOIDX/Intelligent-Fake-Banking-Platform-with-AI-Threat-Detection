import sqlite3
import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import os

DATABASE_PATH = 'mans_bank.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT 0,
            is_blocked BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT UNIQUE NOT NULL,
            balance REAL DEFAULT 0.0,
            available REAL DEFAULT 0.0,
            savings REAL DEFAULT 0.0,
            card_number TEXT,
            FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            counterparty TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            success BOOLEAN NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT NOT NULL,
            analysis TEXT NOT NULL,
            source TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS active_tokens (
            token TEXT PRIMARY KEY,
            user_email TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ai_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            severity TEXT NOT NULL,
            threat_data TEXT,
            is_read BOOLEAN DEFAULT 0,
            is_dismissed BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('SELECT COUNT(*) FROM users WHERE email = ?', ('admin@mans.bank',))
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
            INSERT INTO users (email, password, name, is_admin)
            VALUES (?, ?, ?, ?)
        ''', ('admin@mans.bank', generate_password_hash('admin123'), 'Admin User', True))
        
        cursor.execute('''
            INSERT INTO accounts (user_email, balance, available, savings, card_number)
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin@mans.bank', 12450.87, 10200.00, 2250.87, '4825'))
        
        add_transaction('admin@mans.bank', 'sent', -150.00, 'Payment sent', 'John Doe', conn)
        add_transaction('admin@mans.bank', 'received', 500.00, 'Salary deposit', 'Salary', conn)
        add_transaction('admin@mans.bank', 'purchase', -45.99, 'Purchase', 'Coffee Shop', conn)
    
    conn.commit()
    conn.close()
    print("Database initialized successfully!")

def get_user(email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return dict(user)
    return None

def create_user(email, password, name, is_admin=False):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO users (email, password, name, is_admin)
            VALUES (?, ?, ?, ?)
        ''', (email, generate_password_hash(password), name, is_admin))
        
        card_number = str(secrets.randbelow(9000) + 1000)
        cursor.execute('''
            INSERT INTO accounts (user_email, balance, available, savings, card_number)
            VALUES (?, ?, ?, ?, ?)
        ''', (email, 1000.00, 1000.00, 0.00, card_number))
        
        add_transaction(email, 'received', 1000.00, 'Welcome Bonus', 'MANS Bank', conn)
        
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def verify_password(email, password):
    user = get_user(email)
    if user and check_password_hash(user['password'], password):
        return True
    return False

def is_user_blocked(email):
    user = get_user(email)
    return user and user['is_blocked']

def is_user_admin(email):
    user = get_user(email)
    return user and user['is_admin']

def get_account(email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM accounts WHERE user_email = ?', (email,))
    account = cursor.fetchone()
    
    if account:
        account_dict = dict(account)
        cursor.execute('''
            SELECT * FROM transactions 
            WHERE user_email = ? 
            ORDER BY created_at DESC 
            LIMIT 20
        ''', (email,))
        transactions = cursor.fetchall()
        account_dict['transactions'] = [format_transaction(dict(t)) for t in transactions]
        conn.close()
        return account_dict
    
    conn.close()
    return None

def format_transaction(trans):
    created = trans.get('created_at', '')
    if created:
        try:
            dt = datetime.fromisoformat(created)
            diff = datetime.now() - dt
            if diff.days > 0:
                time_str = f"{diff.days} days ago"
            elif diff.seconds > 3600:
                time_str = f"{diff.seconds // 3600} hours ago"
            elif diff.seconds > 60:
                time_str = f"{diff.seconds // 60} mins ago"
            else:
                time_str = "Just now"
        except:
            time_str = "Recently"
    else:
        time_str = "Recently"
    
    result = {
        'type': trans['type'],
        'amount': trans['amount'],
        'time': time_str
    }
    
    if trans['type'] == 'sent':
        result['to'] = trans.get('counterparty', 'Unknown')
    elif trans['type'] == 'received':
        result['from'] = trans.get('counterparty', 'Unknown')
    else:
        result['at'] = trans.get('counterparty', 'Unknown')
    
    return result

def add_transaction(email, trans_type, amount, description, counterparty, conn=None):
    should_close = False
    if conn is None:
        conn = get_db_connection()
        should_close = True
    
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO transactions (user_email, type, amount, description, counterparty)
        VALUES (?, ?, ?, ?, ?)
    ''', (email, trans_type, amount, description, counterparty))
    
    if should_close:
        conn.commit()
        conn.close()

def get_all_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    
    result = []
    for user in users:
        user_dict = dict(user)
        account = get_account(user_dict['email'])
        result.append({
            'email': user_dict['email'],
            'name': user_dict['name'],
            'isAdmin': user_dict['is_admin'],
            'blocked': user_dict['is_blocked'],
            'account': account
        })
    
    conn.close()
    return result

def add_funds(email, amount):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE accounts 
        SET balance = balance + ?, available = available + ?
        WHERE user_email = ?
    ''', (amount, amount, email))
    
    if amount >= 0:
        add_transaction(email, 'received', amount, 'Admin Credit', 'Admin', conn)
    else:
        add_transaction(email, 'sent', abs(amount), 'Admin Debit', 'Admin', conn)
    
    cursor.execute('SELECT balance FROM accounts WHERE user_email = ?', (email,))
    new_balance = cursor.fetchone()
    
    conn.commit()
    conn.close()
    
    return new_balance[0] if new_balance else 0

def block_user(email, blocked=True):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET is_blocked = ? WHERE email = ?', (blocked, email))
    
    if blocked:
        cursor.execute('DELETE FROM active_tokens WHERE user_email = ?', (email,))
    
    conn.commit()
    conn.close()

def delete_user(email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM active_tokens WHERE user_email = ?', (email,))
    cursor.execute('DELETE FROM transactions WHERE user_email = ?', (email,))
    cursor.execute('DELETE FROM accounts WHERE user_email = ?', (email,))
    cursor.execute('DELETE FROM users WHERE email = ?', (email,))
    conn.commit()
    conn.close()

def generate_token():
    return secrets.token_hex(32)

def save_token(token, email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO active_tokens (token, user_email)
        VALUES (?, ?)
    ''', (token, email))
    conn.commit()
    conn.close()

def get_user_from_token(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT user_email FROM active_tokens WHERE token = ?', (token,))
    result = cursor.fetchone()
    conn.close()
    return result['user_email'] if result else None

def remove_token(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM active_tokens WHERE token = ?', (token,))
    conn.commit()
    conn.close()

def log_login_attempt(email, success, ip_address, user_agent='', reason=''):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO login_logs (email, success, ip_address, user_agent, reason)
        VALUES (?, ?, ?, ?, ?)
    ''', (email, success, ip_address, user_agent, reason))
    conn.commit()
    conn.close()

def get_login_logs(limit=100):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM login_logs 
        ORDER BY created_at DESC 
        LIMIT ?
    ''', (limit,))
    logs = cursor.fetchall()
    conn.close()
    
    return [{
        'timestamp': log['created_at'],
        'email': log['email'],
        'success': bool(log['success']),
        'ip_address': log['ip_address'],
        'user_agent': log['user_agent'],
        'reason': log['reason']
    } for log in logs]

def log_security_event(event_type, description, severity, data=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO security_events (type, description, severity, data)
        VALUES (?, ?, ?, ?)
    ''', (event_type, description, severity, json.dumps(data) if data else None))
    conn.commit()
    conn.close()

def get_security_events(limit=100):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM security_events 
        ORDER BY created_at DESC 
        LIMIT ?
    ''', (limit,))
    events = cursor.fetchall()
    conn.close()
    
    return [{
        'timestamp': event['created_at'],
        'type': event['type'],
        'description': event['description'],
        'severity': event['severity'],
        'data': json.loads(event['data']) if event['data'] else {}
    } for event in events]

def detect_brute_force(email, ip_address):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT COUNT(*) FROM login_logs 
        WHERE success = 0 
        AND (email = ? OR ip_address = ?)
        AND created_at > datetime('now', '-10 minutes')
    ''', (email, ip_address))
    count = cursor.fetchone()[0]
    conn.close()
    
    return count >= 5, count

def add_threat_detection(text, analysis, source):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO threat_detections (text, analysis, source)
        VALUES (?, ?, ?)
    ''', (text[:200], json.dumps(analysis), source))
    conn.commit()
    conn.close()

def get_threat_detections(limit=50):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM threat_detections 
        ORDER BY created_at DESC 
        LIMIT ?
    ''', (limit,))
    threats = cursor.fetchall()
    conn.close()
    
    return [{
        'timestamp': threat['created_at'],
        'text': threat['text'],
        'analysis': json.loads(threat['analysis']),
        'source': threat['source']
    } for threat in threats]

def get_security_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM login_logs')
    total_logins = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM login_logs WHERE success = 0')
    failed_logins = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM login_logs WHERE success = 1')
    successful_logins = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM security_events WHERE type = 'brute_force_detected'")
    brute_force_events = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM security_events WHERE type LIKE '%threat%'")
    threat_events = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM security_events WHERE severity = 'critical'")
    critical_events = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM security_events WHERE severity = 'high'")
    high_events = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM users WHERE is_blocked = 1')
    blocked_users = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM threat_detections')
    total_threats = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        'total_logins': total_logins,
        'failed_logins': failed_logins,
        'successful_logins': successful_logins,
        'brute_force_attempts': brute_force_events,
        'sql_injection_attempts': threat_events,
        'critical_events': critical_events,
        'high_severity_events': high_events,
        'blocked_users_count': blocked_users,
        'total_threats_detected': total_threats
    }

def create_ai_alert(alert_type, title, message, severity, threat_data=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO ai_alerts (alert_type, title, message, severity, threat_data)
        VALUES (?, ?, ?, ?, ?)
    ''', (alert_type, title, message, severity, json.dumps(threat_data) if threat_data else None))
    conn.commit()
    conn.close()

def get_ai_alerts(limit=50, unread_only=False):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if unread_only:
        cursor.execute('''
            SELECT * FROM ai_alerts 
            WHERE is_dismissed = 0 AND is_read = 0
            ORDER BY created_at DESC 
            LIMIT ?
        ''', (limit,))
    else:
        cursor.execute('''
            SELECT * FROM ai_alerts 
            WHERE is_dismissed = 0
            ORDER BY created_at DESC 
            LIMIT ?
        ''', (limit,))
    
    alerts = cursor.fetchall()
    conn.close()
    
    return [{
        'id': alert['id'],
        'alert_type': alert['alert_type'],
        'title': alert['title'],
        'message': alert['message'],
        'severity': alert['severity'],
        'threat_data': json.loads(alert['threat_data']) if alert['threat_data'] else None,
        'is_read': bool(alert['is_read']),
        'created_at': alert['created_at']
    } for alert in alerts]

def mark_alert_read(alert_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE ai_alerts SET is_read = 1 WHERE id = ?', (alert_id,))
    conn.commit()
    conn.close()

def dismiss_alert(alert_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE ai_alerts SET is_dismissed = 1 WHERE id = ?', (alert_id,))
    conn.commit()
    conn.close()

def get_unread_alert_count():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM ai_alerts WHERE is_dismissed = 0 AND is_read = 0')
    count = cursor.fetchone()[0]
    conn.close()
    return count

def get_database_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    stats = {}
    
    cursor.execute('SELECT COUNT(*) FROM users')
    stats['users_count'] = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM accounts')
    stats['accounts_count'] = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM transactions')
    stats['transactions_count'] = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM login_logs')
    stats['login_logs_count'] = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM security_events')
    stats['security_events_count'] = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM threat_detections')
    stats['threat_detections_count'] = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM ai_alerts')
    stats['ai_alerts_count'] = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM active_tokens')
    stats['active_tokens_count'] = cursor.fetchone()[0]
    
    conn.close()
    return stats

def get_table_data(table_name, limit=100, offset=0):
    allowed_tables = ['login_logs', 'security_events', 'threat_detections', 'ai_alerts']
    
    if table_name not in allowed_tables:
        return []
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(f'SELECT * FROM {table_name} ORDER BY created_at DESC LIMIT ? OFFSET ?', (limit, offset))
    rows = cursor.fetchall()
    conn.close()
    
    result = []
    for row in rows:
        row_dict = dict(row)
        for key, value in row_dict.items():
            if key == 'data' or key == 'analysis' or key == 'threat_data':
                try:
                    row_dict[key] = json.loads(value) if value else None
                except:
                    pass
        result.append(row_dict)
    
    return result

def clear_table_data(table_name):
    clearable_tables = ['login_logs', 'security_events', 'threat_detections', 'ai_alerts']
    
    if table_name not in clearable_tables:
        return False, "Cannot clear this table"
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(f'SELECT COUNT(*) FROM {table_name}')
    count_before = cursor.fetchone()[0]
    
    cursor.execute(f'DELETE FROM {table_name}')
    
    conn.commit()
    conn.close()
    
    return True, f"Cleared {count_before} records from {table_name}"

def clear_old_logs(days=30):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cleared = {}
    
    cursor.execute('''
        DELETE FROM login_logs 
        WHERE created_at < datetime('now', '-' || ? || ' days')
    ''', (days,))
    cleared['login_logs'] = cursor.rowcount
    
    cursor.execute('''
        DELETE FROM security_events 
        WHERE created_at < datetime('now', '-' || ? || ' days')
    ''', (days,))
    cleared['security_events'] = cursor.rowcount
    
    cursor.execute('''
        DELETE FROM threat_detections 
        WHERE created_at < datetime('now', '-' || ? || ' days')
    ''', (days,))
    cleared['threat_detections'] = cursor.rowcount
    
    cursor.execute('''
        DELETE FROM ai_alerts 
        WHERE created_at < datetime('now', '-' || ? || ' days')
        AND is_dismissed = 1
    ''', (days,))
    cleared['ai_alerts'] = cursor.rowcount
    
    conn.commit()
    conn.close()
    
    return cleared

def get_alert_by_id(alert_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM ai_alerts WHERE id = ?', (alert_id,))
    alert = cursor.fetchone()
    conn.close()
    
    if alert:
        alert_dict = dict(alert)
        if alert_dict.get('threat_data'):
            try:
                alert_dict['threat_data'] = json.loads(alert_dict['threat_data'])
            except:
                pass
        return alert_dict
    return None

def update_alert_analysis(alert_id, analysis_data):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT threat_data FROM ai_alerts WHERE id = ?', (alert_id,))
    result = cursor.fetchone()
    
    if result:
        existing_data = json.loads(result['threat_data']) if result['threat_data'] else {}
        existing_data['ai_analysis'] = analysis_data
        
        cursor.execute('''
            UPDATE ai_alerts 
            SET threat_data = ?, is_read = 1 
            WHERE id = ?
        ''', (json.dumps(existing_data), alert_id))
        
        conn.commit()
        conn.close()
        return True
    
    conn.close()
    return False

if __name__ == '__main__':
    init_database()
