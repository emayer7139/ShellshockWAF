
  .--.--.     ,---,                ,--,    ,--,     .--.--.     ,---,                              ,-.
 /  /    '. ,--.' |              ,--.'|  ,--.'|    /  /    '. ,--.' |                          ,--/ /|
|  :  /`. / |  |  :              |  | :  |  | :   |  :  /`. / |  |  :       ,---.     ,---.  ,--. :/ |
;  |  |--`  :  :  :              :  : '  :  : '   ;  |  |--`  :  :  :      '   ,'\   '   ,'\ :  : ' /
|  :  ;_    :  |  |,--.   ,---.  |  ' |  |  ' |   |  :  ;_    :  |  |,--. /   /   | /   /   ||  '  /
 \  \    `. |  :  '   |  /     \ '  | |  '  | |    \  \    `. |  :  '   |.   ; ,. :.   ; ,. :'  |  :
  `----.   \|  |   /' : /    /  ||  | :  |  | :     `----.   \|  |   /' :'   | |: :'   | |: :|  |   \
  __ \  \  |'  :  | | |.    ' / |'  : |__'  : |__   __ \  \  |'  :  | | |'   | .; :'   | .; :'  : |. \
 /  /`--'  /|  |  ' | :'   ;   /||  | '.'|  | '.'| /  /`--'  /|  |  ' | :|   :    ||   :    ||  | ' \ \
'--'.     / |  :  :_:,''   |  / |;  :    ;  :    ;'--'.     / |  :  :_:,' \   \  /  \   \  / '  : |--'
  `--'---'  |  | ,'    |   :    ||  ,   /|  ,   /   `--'---'  |  | ,'      `----'    `----'  ;  |,'
            `--''       \   \  /  ---`-'  ---`-'              `--''                          '--'
                         `----'

                            S h e l l s h o c k   &   C G I   W A F
A simple, host-based WAF to block Shellshock-style Bash exploits and related CGI injection attacks on Ubuntu servers running Apache, NGINX, and PHP—no ModSecurity required. Clone this repo and run the bootstrap script on each target host to instantly deploy multi-layer defenses.


## Repository Contents

```
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
```
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
   ```bash
   sudo chmod +x test_waf.sh
   sudo ./test_waf.sh
   ```
   This will go over each aspect of the code for nginx, apache, fail2ban, and check your bash version. This test does work for continers as well. 

## Contributing
   1. Fork repository
   2. Create feature branch: git checkout -b feature/my-waf-rule
   3. Commit your changes: git commit -am "Add new rule"
   4. Push branch: git push origin feature/my-waf-rule
   5. Open a Pull Request


