import time
from zapv2 import ZAPv2

target_url = 'http://juice-shop:3000'
zap = ZAPv2(proxies={'http': 'http://zap:8080', 'https': 'http://zap:8080'}, apikey='jangijoim_zap_key')

print("1. Spider")
scan_id = zap.spider.scan(target_url)
while int(zap.spider.status(scan_id)) < 100:
    time.sleep(2)
    print(f"Spider: {zap.spider.status(scan_id)}%")

print("2. Ajax Spider")
zap.ajaxSpider.scan(target_url)
while zap.ajaxSpider.status == 'running':
    time.sleep(5)
    print("Ajax Spider running...")

print("3. Active Scan")
scan_id = zap.ascan.scan(target_url)
while int(zap.ascan.status(scan_id)) < 100:
    time.sleep(5)
    print(f"Active Scan: {zap.ascan.status(scan_id)}%")

alerts = zap.core.alerts()
print(f"Alerts found: {len(alerts)}")
for a in alerts[:5]:
    print(a.get('alert'), a.get('risk'))
