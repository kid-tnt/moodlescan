# moodlescan
## Installation and requirements

- Install Python 3
- Install the package python3-pip
- Clone this repository: git clone https://github.com/inc0d3/moodlescan.git
- cd moodlescan/
- run: pip install -r requirements.txt
- python moodlescan.py -u [URL]

## Usage
```
Options

		-u [URL] 	: URL with the target, the moodle to scan
		-a 		: Update the database of vulnerabilities to latest version
		-r 		: Enable HTTP requests with random user-agent
		-k 		: Ignore SSL Certificate

		Proxy configuration

		-p [URL]	: URL of proxy server (http)
		-b [user]	: User for authenticate to proxy server
		-c [password]	: Password for authenticate to proxt server
		-d [protocol]  : Protocol of authentication: basic or ntlm


```
## Changes

1.0 Modified by NgoVanThang_B18DCAT240
- Update database of vulnerabilities and versions
- Fix scan vulnerabilities logic
- Vulnerability scanning is now working as expected

0.8

- Update database of vulnerabilities and versions
- Fix error for bad URL format
- Change URL in tests - one is offline and trigger an error

0.7

- Added -k option for Ignore SSL Certificate
- Added a file for error logs

0.6

- Update database of vulnerabilities and versions
- Update version scan algorithm
- Update vulnerability report
- Added Random user-agent support
- Fix encoding errors

0.5

- Cambios para operar con Python 3.7+
- Se corrige algoritmo para determinar la versión
- Se corrigen errores reportados

0.4

- Opciones para utilizar proxy
- Nuevas vulnerabilidades en base de datos

0.3

- Version inicial

## Autor original

* **Víctor Herrera** 
