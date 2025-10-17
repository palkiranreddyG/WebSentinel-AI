import logging
from app.ml_model.url_predictor import predict_url_threat
from app.ml_model.content_predictor import predict_content_threat
from app.scraper import scrape_content
from app.utils import generate_reason
from urllib.parse import urlparse
import whois
import dns.resolver
import requests
from datetime import datetime

# Set up logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def analyze_url(url):
    # Log the URL being analyzed
    logger.info(f"Analyzing URL: {url}")

    # Predict URL threat
    try:
        url_score, features_detected = predict_url_threat(url)
    except Exception as e:
        logger.error(f"Failed to predict URL threat for {url}: {str(e)}")
        raise

    # Scrape content and predict content threat
    content = None
    content_score = 0.0
    try:
        content = scrape_content(url)
        content_score = predict_content_threat(content)
    except Exception as e:
        logger.warning(f"Failed to scrape or predict content for {url}: {str(e)}")
        content = ""
        content_score = 0.0

    final_score = url_score  # For now, use URL score as final score

    # Determine label and verdict
    if final_score > 0.75:  # Adjusted threshold to match url_predictor.py
        label = "Malicious"
        verdict = "🛑 HIGH RISK"
    elif final_score > 0.5:
        label = "Suspicious"
        verdict = "⚠️ SUSPICIOUS"
    else:
        label = "Safe"
        verdict = "✅ LIKELY SAFE"

    # Generate reasons using utils.generate_reason
    reasons = generate_reason(url, content)

    # Extract domain
    domain = urlparse(url).netloc

    # Domain Age
    domain_age = "Unknown"
    try:
        w = whois.whois(domain)
        if w.creation_date:
            creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            age = (datetime.now() - creation_date).days // 365
            domain_age = f"{age} years ago"
    except Exception as e:
        logger.warning(f"Failed to fetch WHOIS for {domain}: {str(e)}")

    # HTTP Status Code
    http_status = "N/A"
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        http_status = response.status_code
    except Exception as e:
        logger.warning(f"Failed to fetch HTTP status for {url}: {str(e)}")

    # SPF/DMARC Record
    spf_dmarc = "Not found"
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text()
            if "v=spf1" in txt.lower():
                spf_dmarc = "SPF found"
                break
            if "v=DMARC1" in txt.lower():
                spf_dmarc = "DMARC found"
                break
    except Exception as e:
        logger.warning(f"Failed to fetch DNS records for {domain}: {str(e)}")

    # Free Hosted Content
    free_hosted = False
    free_hosting_domains = ['wordpress.com', 'wixsite.com', 'weebly.com', 'blogspot.com']
    free_hosted = any(free_domain in domain for free_domain in free_hosting_domains)

    # Parked Domain
    parked_domain = "Not Parked"
    try:
        if content and any(keyword in content.lower() for keyword in ["domain for sale", "parked domain", "buy this domain"]):
            parked_domain = "Possibly Parked"
    except Exception as e:
        logger.warning(f"Failed to check parked domain for {url}: {str(e)}")

    # Log the result
    logger.info(f"Analysis complete for {url}. Verdict: {verdict}, Probability: {final_score}")

    return {
        "url": url,
        "domain": domain,
        "probability": round(final_score, 2),
        "verdict": verdict,
        "features_detected": features_detected,
        "total_features": 116,  # Updated to reflect new feature count
        "reasons": reasons,
        "domain_age": domain_age,
        "http_status": http_status,
        "spf_dmarc": spf_dmarc,
        "free_hosted": "Yes" if free_hosted else "No",
        "parked_domain": parked_domain
    }