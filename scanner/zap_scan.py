# scanner/zap_scan.py
from zapv2 import ZAPv2
import time
import os

ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")  # set if you enabled API key
ZAP_HOST = os.environ.get("ZAP_HOST", "127.0.0.1")
ZAP_PORT = int(os.environ.get("ZAP_PORT", "8080"))
ZAP_PROXY = {
    'http': f'http://{ZAP_HOST}:{ZAP_PORT}',
    'https': f'http://{ZAP_HOST}:{ZAP_PORT}'
}
zap = ZAPv2(apikey=ZAP_API_KEY, proxies=ZAP_PROXY)

def start_zap(target_url):
    """Run OWASP ZAP scan on target_url and return vulnerabilities"""
    # Open target URL
    zap.urlopen(target_url)
    time.sleep(2)

    # Spider scan
    spider_id = zap.spider.scan(target_url)
    while int(zap.spider.status(spider_id)) < 100:
        time.sleep(1)

    # Active scan
    scan_id = zap.ascan.scan(target_url)
    while int(zap.ascan.status(scan_id)) < 100:
        time.sleep(2)

    # Collect vulnerabilities
    alerts = zap.core.alerts(baseurl=target_url)
    vulns = [{"name": a.get("name"), "url": a.get("url"), "risk": a.get("risk")} for a in alerts]

    return {
        "spider": "100%",
        "active": "100%",
        "vulnerabilities": vulns
    }