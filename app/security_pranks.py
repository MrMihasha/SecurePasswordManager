import re
from flask import session

# Common XSS payloads
XSS_PATTERNS = [
    r'<script[^>]*>.*?</script>',
    r'javascript:',
    r'onerror\s*=',
    r'onload\s*=',
    r'onclick\s*=',
    r'<img[^>]+src[^>]*>',
    r'alert\s*\(',
    r'prompt\s*\(',
    r'confirm\s*\(',
    r'document\.cookie',
    r'<iframe',
    r'<object',
    r'<embed',
]

# Common SQL injection payloads
SQLI_PATTERNS = [
    r"'\s*(or|OR)\s*'?1'?\s*=\s*'?1",
    r"'\s*(or|OR)\s*1\s*=\s*1",
    r";\s*drop\s+table",
    r";\s*drop\s+database",
    r"union\s+select",
    r"'\s*--",
    r"'\s*#",
    r"admin'\s*--",
    r"'\s*or\s*'.*'\s*=\s*'",
    r"1=1",
    r"'\s*;\s*select",
]

# Path traversal
PATH_TRAVERSAL_PATTERNS = [
    r'\.\./\.\./',
    r'\.\.\\\.\.\\',
    r'/etc/passwd',
    r'C:\\Windows',
]

# Command injection
COMMAND_INJECTION_PATTERNS = [
    r';\s*ls\s*',
    r';\s*cat\s*',
    r';\s*rm\s*',
    r'\|\s*ls',
    r'\|\s*cat',
    r'`.*`',
    r'\$\(.*\)',
]

# Fun responses based on attack type
HACKER_RESPONSES = {
    'xss': {
        'title': '🚨 XSS Attempt Detected! 🚨',
        'message': "Nice try, hacker! But my app auto-escapes everything with Jinja2! 😎",
        'tips': [
            "Pro tip: Content Security Policy headers block inline scripts",
            "This app uses automatic HTML escaping - XSS won't work here!",
            "Even if you bypass the frontend, the backend validates everything 🛡️"
        ],
        'meme': 'xss_blocked.gif'
    },
    'sqli': {
        'title': '💉 SQL Injection Detected! 💉',
        'message': "Did you really think parameterized queries wouldn't stop you? 😂",
        'tips': [
            "This app uses SQLAlchemy ORM - no raw SQL here!",
            "Every query is parameterized and escaped automatically",
            "Nice try with that UNION SELECT though! Classic move 👌"
        ],
        'meme': 'sqli_failed.gif'
    },
    'path_traversal': {
        'title': '📁 Path Traversal Detected! 📁',
        'message': "../../etc/passwd? Really? That's a 90s move! 🦖",
        'tips': [
            "All file paths are validated and sanitized",
            "No directory traversal allowed here, buddy!",
            "This isn't a PHP app from 2005 😉"
        ],
        'meme': 'path_blocked.gif'
    },
    'command_injection': {
        'title': '⚡ Command Injection Detected! ⚡',
        'message': "Trying to run shell commands? Bold move! 🎯",
        'tips': [
            "No shell commands are executed from user input",
            "Everything is properly escaped and validated",
            "This app doesn't trust ANYONE - not even itself! 🔐"
        ],
        'meme': 'command_blocked.gif'
    },
    'generic': {
        'title': '🤔 Suspicious Activity Detected! 🤔',
        'message': "I see what you're trying to do there... 👀",
        'tips': [
            "This app is built with security in mind from day one",
            "CSRF tokens, rate limiting, input validation - we got it all!",
            "But hey, thanks for testing the security! 🙏"
        ],
        'meme': 'suspicious.gif'
    }
}

# Easter eggs for specific inputs
EASTER_EGGS = {
    'bobby tables': {
        'title': "🎉 XKCD Reference Detected! 🎉",
        'message': "Ah, a cultured hacker! Little Bobby Tables would be proud! 👦",
        'image': 'bobby_tables.png',
        'reference': 'https://xkcd.com/327/'
    },
    'test\'; drop table passwords;--': {
        'title': "🎭 Classic SQL Injection Attempt! 🎭",
        'message': "The legendary Bobby Tables attack! But sorry, we use an ORM 😉",
        'image': 'bobby_tables.png'
    },
    'admin': {
        'title': "👑 Admin Vibes! 👑",
        'message': "Looking for admin? There's no secret admin panel here! (Or is there? 🤔)",
        'tips': ["Spoiler: There isn't. But nice try!"]
    },
    '1=1': {
        'title': "🎯 1=1 Detected! 🎯",
        'message': "The most basic SQL injection! Where did you learn this, 2010? 😄",
    }
}


def detect_attack(input_string):
    """
    Detect common attack patterns in user input
    Returns attack type and response data
    """
    if not input_string or len(input_string) < 2:
        return None
    
    input_lower = input_string.lower()
    
    # Check for Easter eggs first (exact matches)
    for egg_trigger, egg_data in EASTER_EGGS.items():
        if egg_trigger.lower() in input_lower:
            return ('easter_egg', egg_data)
    
    # Check for XSS
    for pattern in XSS_PATTERNS:
        if re.search(pattern, input_string, re.IGNORECASE):
            return ('xss', HACKER_RESPONSES['xss'])
    
    # Check for SQL injection
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, input_string, re.IGNORECASE):
            return ('sqli', HACKER_RESPONSES['sqli'])
    
    # Check for path traversal
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, input_string, re.IGNORECASE):
            return ('path_traversal', HACKER_RESPONSES['path_traversal'])
    
    # Check for command injection
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, input_string, re.IGNORECASE):
            return ('command_injection', HACKER_RESPONSES['command_injection'])
    
    return None


def increment_hacker_score():
    """Track how many times user tries to hack"""
    if 'hacker_attempts' not in session:
        session['hacker_attempts'] = 0
    session['hacker_attempts'] += 1
    return session['hacker_attempts']


def get_hacker_rank(attempts):
    """Get funny hacker rank based on attempts"""
    if attempts >= 10:
        return "🏆 Elite Hacker (or just bored)"
    elif attempts >= 7:
        return "💪 Persistent Script Kiddie"
    elif attempts >= 5:
        return "🎓 Junior Penetration Tester"
    elif attempts >= 3:
        return "🐣 Curious Newbie"
    else:
        return "👀 Security Enthusiast"


def get_funny_fact():
    """Random security facts"""
    import random
    facts = [
        "💡 The first computer bug was an actual bug (a moth) found in 1947!",
        "🔐 The password '123456' is still the most common password in 2024!",
        "🎯 SQL injection was discovered in 1998 and is STILL in the OWASP Top 10!",
        "🌍 Over 30,000 websites are hacked every day!",
        "⏱️ It takes only 10 minutes to crack an 8-character password with modern GPUs!",
        "🎓 'Password' is used as a password by 4.7% of people!",
        "🛡️ Two-factor authentication blocks 99.9% of automated attacks!",
        "🐛 The average cost of a data breach is $4.45 million!",
        "👨‍💻 The term 'hacker' originally meant someone who was very skilled at programming!",
        "🎪 The first recorded cyber attack was in 1988 (the Morris Worm)!"
    ]
    return random.choice(facts)
