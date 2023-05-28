import sys
from files.logos import render
from files.colors import text_color

import requests

W = text_color("white")
C = text_color("cyan")
Y = text_color("yellow")
R = text_color('red')
G = text_color("green")


def check_vulnerabilities(url, ssrf_url):
    try:
        response = requests.get(url)
        headers = response.headers

        # Check for common vulnerability-related headers
        if 'Server' in headers:
            print(f"{W}[+] {G}Server header found: {R}{headers['Server']} {G}(May reveal server details)")

        if 'X-Frame-Options' not in headers:
            print(f"{W}[-] {G}X-Frame-Options header missing {C}(Clickjacking vulnerability)")

        if 'Content-Security-Policy' not in headers:
            print(f"{W}[-] {G}Content-Security-Policy header missing {C}(Potential XSS vulnerability)")

        if 'Strict-Transport-Security' not in headers:
            print(f"{W}[-] {G}Strict-Transport-Security header missing {C}(HTTP to HTTPS downgrade vulnerability)")

        if 'X-XSS-Protection' not in headers:
            print(f"{W}[-] {G}X-XSS-Protection header missing {C}(Potential XSS vulnerability)")

        if 'X-Content-Type-Options' not in headers:
            print(f"{W}[-] {G}X-Content-Type-Options header missing (MIME sniffing vulnerability)")

        # Check for IDOR vulnerability
        if 'Location' in headers:
            if response.status_code == 302 and response.headers['Location'].startswith('/'):
                print(f"{W}[-] {G}Insecure Direct Object References (IDOR) vulnerability detected")

        # Check for absence of a Web Application Firewall (WAF)
        if 'X-CDN' not in headers and 'X-Firewall' not in headers:
            print(f"{W}[-] {G}Web Application Firewall (WAF) not detected")

        # Check for SQL Injection vulnerability
        payload = " ' OR '1'='1' --"
        try:
            print(f'{W}[+] {Y}Detecting SqlI')
            injected_url = url + payload
            print(f'{W}[~] {G}Trying Payload: {R}{injected_url}')
            injected_response = requests.get(injected_url)
            if injected_response.text != response.text:
                print(f"{W}[-] {G}Potential SQL Injection vulnerability detected")
        except Exception as e:
            print(f'{W}[!] {R}Error occurred: {e}')

        # Check for SSRF vulnerability
        try:
            print(f'{W}[+] {Y}Detecting SSRF')
            ssrf_test_url = ssrf_url  # Replace with your test SSRF URL
            ssrf_response = requests.get(ssrf_test_url)
            if ssrf_response.status_code == 200:
                print(f"{W}[-] {G}Potential Server-side Request Forgery (SSRF) vulnerability detected")
        except Exception as e:
            print(f'{W}[!] {R}Error occurred: {e}')

        # Check for RCE vulnerability
        try:
            print(f'{W}[+] {Y}Detecting RCE')
            rce_test_command = "ping 127.0.0.1"
            print(f'{W}[~] {G}Trying command: {R}{rce_test_command}')
            rce_test_url = f"{url}?param={rce_test_command}"
            print(f'{W}[?] {C}RCE test URL: {R}{rce_test_url}')
            rce_response = requests.get(rce_test_url)
            if "127.0.0.1" in rce_response.text:
                print(f"{W}[-] {G}Potential Remote Code Execution (RCE) vulnerability detected")
        except Exception as e:
            print(f'{W}[!] {R}Error occurred: {e}')

        # Check for Path Traversal vulnerability
        try:
            print(f'{W}[+] {Y}Detecting Path Traversal')
            path_traversal_test_url = f"{url}?file=../../../etc/passwd"
            print(f'{W}[~] {C}Trying URL: {R}{path_traversal_test_url}')
            path_traversal_response = requests.get(path_traversal_test_url)
            if "root:" in path_traversal_response.text:
                print(f"{W}[-] {G}Potential Path Traversal vulnerability detected")
        except Exception as e:
            print(f'{W}[!] {R}Error occurred {e}')

    except requests.exceptions.RequestException as e:
        print(f"{W}[!] {R}An error occurred: {e}")


if len(sys.argv) < 3:
    print(render())
    print(f'{W}[>] {Y}Usage: {C}{sys.argv[0]} {R}<website_url> {R}<ssrf_url>')
    exit(0)

print(render())
website_url = sys.argv[1]
ssrf_url = sys.argv[2]
check_vulnerabilities(website_url, ssrf_url)
