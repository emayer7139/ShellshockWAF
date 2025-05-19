# ShellshockWAF
A simple, host-based WAF to block Shellshock-style Bash exploits and related CGI injection attacks on Ubuntu servers running Apache, NGINX, and PHP—no ModSecurity required. Clone this repo and run the bootstrap script on each target host to instantly deploy multi-layer defenses.


## Repository Contents


├── deploy-waf.sh # Bootstrap installer script
├── README.md # This file
├── nginx/ # NGINX config snippets
│ └── shellshock.conf
└── apache/ # Apache config snippets
└── shellshock.conf
└── fail2ban/ # Fail2Ban filters & jails
├── filter.d
│ ├── apache-shellshock.conf
│ └── nginx-shellshock.conf
└── jail.local

---

## Prerequisites

- Ubuntu **20.04**, **22.04**, or **24.04** LTS  
- **root** or sudo-privileged user  
- Internet access to install packages

---

## Quick Install

1. ## **Clone the repo** on your target host:
   ```bash
   git clone https://github.com/your-org/lightweight-shellshock-waf.git
   cd lightweight-shellshock-waf

2. ## Run the bootstrap script:
   ```bash
   sudo bash deploy-waf.sh

3. ## Testing Your WAF
   Shellshock Ban Test

   ### Should NOT return "vulnerable"
   env x='() { :;}; echo vulnerable' bash -c "echo this is a test"

   ### Should be dropped by iptables (no response):
   printf "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: () { :;}; echo PWNED\r\n\r\n" | nc localhost 80

   ### Apache 403 test:
   curl -I -H 'User-Agent: () { :;}; echo PWNED' http://localhost/

   ### NGINX 403 test:
   curl -I -H 'User-Agent: () { :;}; echo PWNED' http://localhost/

   ### Fail2Ban match test:
   sudo fail2ban-regex /var/log/apache2/error.log /etc/fail2ban/filter.d/apache-shellshock.conf


## Contributing
   1. Fork repository
   2. Create feature branch: git checkout -b feature/my-waf-rule
   3. Commit your changes: git commit -am "Add new rule"
   4. Push branch: git push origin feature/my-waf-rule
   5. Open a Pull Request


