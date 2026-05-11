# scanner/zap_scan.py
from zapv2 import ZAPv2
import time

ZAP_API_KEY = ""  # set if you enabled API key
ZAP_PROXY = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
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