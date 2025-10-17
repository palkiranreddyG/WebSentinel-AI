import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_reason(url, content):
    try:
        reasons = []
        # Check for HTTPS
        if 'http://' in url or 'https://' not in url:
            reasons.append("Missing HTTPS")
        
        # Check for phishing keywords in content, but only if content is not None
        if content:
            if any(keyword in content.lower() for keyword in ["login", "verify", "reset", "urgent", "password"]):
                reasons.append("Phishing-related keywords found")
        
        # Check URL length
        if len(url) > 75:
            reasons.append("URL length suspicious")
        
        # Default reason if no issues found
        if not reasons:
            reasons.append("None")
        
        return ", ".join(reasons)  # Join reasons into a string to match model.py expectations
    except Exception as e:
        logger.error(f"Error generating reasons for URL {url}: {str(e)}")
        return "Error generating reasons"