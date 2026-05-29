import json
import requests

# [Example] OWASP Juice Shop Login Script
def get_session():
    target_url = "http://juice-shop:3000/rest/user/login"
    payload = {
        "email": "admin@juice-sh.op",
        "password": "admin123" # Default password for demonstration
    }
    
    try:
        response = requests.post(target_url, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            token = data.get("authentication", {}).get("token")
            
            # stdout으로 JSON 결과를 출력해야 파이프라인에서 인식함
            print(json.dumps({
                "headers": {
                    "Authorization": f"Bearer {token}"
                },
                "cookies": response.cookies.get_dict()
            }))
        else:
            exit(1)
    except Exception:
        exit(1)

if __name__ == "__main__":
    get_session()
