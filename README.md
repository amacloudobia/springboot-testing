# Basic scan
python3 springhunt.py -u https://target.com

# With Burp proxy + verbose
python3 springhunt.py -u https://target.com -v --proxy http://127.0.0.1:8080

# With session cookie + save report
python3 springhunt.py -u https://target.com --cookies "session=abc" -o report.txt

# Continuous httptrace session harvesting (get written authorization first!)
python3 springhunt.py -u https://target.com --harvest --harvest-rounds 30 --harvest-interval 3
