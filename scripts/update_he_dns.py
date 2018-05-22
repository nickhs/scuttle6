import sys
import requests

URL = "https://dns.he.net/index.cgi"
PARENT = "2605:2700:1:1019:"

def make_req(cookie, name, suffix):
    data = {
        'action': 'add',
        'domid': '764527',
        'menu': 'edit_reverse',
        'type':	'ajax',
        'name': name,
        'suffix': suffix
    }

    cookies = {
        'CGISESSID': cookie
    }

    return requests.post(
        url=URL,
        data=data,
        cookies=cookies,
    )

def main():
    ips = open(sys.argv[1]).readlines()
    names = open(sys.argv[2]).readlines()
    assert(len(ips) == len(names))
    todo = zip(ips, names)
    cookie = sys.argv[3]

    for (ip, name) in todo:
        ip = ip.strip()
        name = name.strip()
        assert(ip.startswith(PARENT))
        assert(' ' not in name)
        ip = ip[len(PARENT):]
        resp = make_req(cookie, name, ip)
        print(resp, resp.json())

if __name__ == "__main__":
    main()
