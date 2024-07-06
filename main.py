# MangaDex Downloader v1.0.0 By @lkse: A Downloader For MangaDex, an online manga reader (https://mangadex.org).
# Requires a MangaDex account /w a Personal API Client.
# This Version is compatible with and built for MangaDex API v5.10.2

# Importing Required Modules
import json
import logging
import os
import requests
from base64 import urlsafe_b64encode, b64encode, urlsafe_b64decode, b64decode
from bcrypt import hashpw, gensalt
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from dotenv import load_dotenv
from rich import pretty
from rich.console import Console
from rich.logging import RichHandler
from rich.prompt import Prompt
from time import sleep
# Setting Up Logging, Console, and global variables
pretty.install()
console = Console()
logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
log = logging.getLogger("rich")
expires_at = None
refresh_expires_at = None
cls = lambda: os.system("cls")

def env_create(username: str, password: str, client_id: str, client_secret: str) -> bool:
    """
    Takes the User's and API Client's Credentials and Creates an encrypted .env file.

    Parameters:
    - username (str): The username of the user.
    - password (str): The password of the user.
    - client_id (str): The client ID of the API client.
    - client_secret (str): The client secret of the API client.

    Returns:
    - bool: Returns True if the function executed successfully, otherwise False.

    """
    status = console.status("[bold]Creating Encrypted Credentials...[/bold]", spinner="dots")
    try:
        status.start()
        log.info("Creating Encrypted Credentials...")
        # Hash The Password
        log.debug("Hashing Password...")
        salt = gensalt()
        log.debug(f"Password Salt: [bold cyan]{salt}[/bold cyan]", extra={"markup": True})
        hashed_password = hashpw(password.encode(), salt)
        log.debug(f"Hashed Password: [bold cyan]{hashed_password}[/bold cyan]", extra={"markup": True})

        log.debug("Encrypting Credentials...")
        key = urlsafe_b64encode(hashed_password[:32])
        log.debug(f"Key: [bold cyan]{key}[/bold cyan]", extra={"markup": True})
        cipher_suite = Fernet(key)

        creds = f"username={username}\npassword={password}\nclient_id={client_id}\nclient_secret={client_secret}"
        enc_creds = cipher_suite.encrypt(creds.encode())
        log.debug(f"Encrypted Credentials: [bold cyan]{enc_creds}[/bold cyan]", extra={"markup": True})

        log.debug("Writing Encrypted Credentials to b64...")
        enc_creds_b64 = b64encode(enc_creds)
        log.debug(f"Encrypted Credentials (b64): [bold cyan]{enc_creds_b64}[/bold cyan]", extra={"markup": True})
        salt_b64 = b64encode(salt)
        log.debug(f"Salt (b64): [bold cyan]{salt_b64}[/bold cyan]", extra={"markup": True})

        log.debug("Writing Encrypted Credentials to disk...")
        try:
            with open(".env", "wb") as file:
                file.write(b"KEY=" + key + b"\n")
                file.write(b"SALT=" + salt_b64 + b"\n")
                file.write(b"ENC_CREDS=" + enc_creds_b64 + b"\n")
        except Exception:
            log.exception(f"An Error Occurred While Writing Encrypted Credentials to Disk.")
            if os.path.exists(".env"):
                log.info("Cleaning Up...")
                os.remove(".env")
                log.info("All Cleaned Up. Returning...")
                status.stop()
                return 0

        log.info("Credentials Successfully Encrypted and Written to Disk.")
    except Exception:
        log.exception("An Error Occurred While Creating Encrypted Credentials.")
        status.stop()
        return 0
    status.stop()
    return 1

def read_env(key: str) -> bool:
    """
    Reads the encrypted credentials from the .env file and decrypts them using the provided 'key'.
    The decrypted credentials are then loaded into the os.environ dictionary.
    
    Parameters:
    - key: The key used for decrypting the credentials.

    Raises:
    - ValueError: If the provided key is different from the key used for encrypting the credentials.

    Returns:
    - bool: Returns True if the function executed successfully, otherwise False.
    """
    status = console.status("[bold]Decrypting Credentials...[/bold]", spinner="dots")
    try:
        status.start()
        log.info("Reading Encrypted Credentials...")
        log.debug("Reading Encrypted Credentials from Disk...")
        load_dotenv()
        salt_b64 = os.environ.get("SALT")
        log.debug(f"Salt (b64): [bold cyan]{salt_b64}[/bold cyan]", extra={"markup": True})
        enc_creds_b64 = os.environ.get("ENC_CREDS")
        log.debug(f"Encrypted Credentials (b64): [bold cyan]{enc_creds_b64}[/bold cyan]", extra={"markup": True})
        envkey = os.environ.get("KEY")
        log.debug(f"Environ Key: [bold cyan]{envkey}[/bold cyan]", extra={"markup": True})

        log.debug("Decoding Encrypted Credentials...")
        salt = b64decode(salt_b64)
        log.debug(f"Decoded Salt: [bold cyan]{salt}[/bold cyan]", extra={"markup": True})
        enc_creds = b64decode(enc_creds_b64)
        log.debug(f"Decoded Encrypted Credentials: [bold cyan]{enc_creds}[/bold cyan]", extra={"markup": True})

        log.debug("Decrypting Credentials...")
        hashed_key = hashpw(key.encode(), salt)
        log.debug(f"Hashed Key: [bold cyan]{hashed_key}[/bold cyan]", extra={"markup": True})
        key_b64 = urlsafe_b64encode(hashed_key[:32]).decode()
        log.debug(f"Key (b64): [bold cyan]{key_b64}[/bold cyan]", extra={"markup": True})
        cipher_suite = Fernet(key_b64)

        if envkey != key_b64:
            log.error("Key Mismatch. The Provided Key is Different from the Key Used for Encrypting the Credentials.")
            status.stop()
            return 0

        log.info("Key Matched. Decrypting Credentials...")
        dcreds = cipher_suite.decrypt(enc_creds)
        decoded_creds = dcreds.decode()

        for line in decoded_creds.split('\n'):
            if line:
                key, value = line.split('=', 1)
                os.environ[key] = value.strip()

        log.info("Credentials Successfully Decrypted.")
    except Exception:
        log.exception("An Error Occurred While Reading Encrypted Credentials.")
        status.stop()
        return 0
    status.stop()
    return 1

def init()-> bool:
    """
    Initializes the Environment:
    - Creates / Reads Encrypted Credentials and Loads them into the os.environ dictionary, /w user input.

    Returns:
    - bool: Returns True if the Environment was initialized successfully, otherwise False.
    """
    log.info("Initializing Environment...")
    try:
        if not os.path.exists(".env"):
            log.debug("No Encrypted Credentials Found.")
            username = Prompt.ask("Enter your [italic gold3]MangaDex[/italic gold3] [blink bold italic chartreuse1]Username: [/blink bold italic chartreuse1]")
            os.environ["username"] = username
            password = Prompt.ask("Enter your [italic gold3]MangaDex[/italic gold3] [blink bold italic chartreuse1]Password: [/blink bold italic chartreuse1]")
            os.environ["password"] = password
            client_id = Prompt.ask("Enter your [italic gold3]Personal API[/italic gold3] [blink bold italic chartreuse1]Client ID: [/blink bold italic chartreuse1]")
            os.environ["client_id"] = client_id
            client_secret = Prompt.ask("Enter your [italic gold3]Personal API[/italic gold3] [blink bold italic chartreuse1]Client Secret: [/blink bold italic chartreuse1]")
            os.environ["client_secret"] = client_secret
            env_create(username, password, client_id, client_secret)

        else:
            log.debug("Encrypted Credentials Found.")
            password = Prompt.ask("\nEnter your [italic gold3]MangaDex[/italic gold3] [blink bold italic chartreuse1]Password: [/blink bold italic chartreuse1]")
            read_env(password)
    except Exception:
        log.exception("An Error Occurred While Initializing the Environment.")
        return 0
    
    return 1

def auth():
    """
    Authenticates the API Client using the credentials in environ.
    """
    status = console.status("[bold]Authenticating API Client...[/bold]", spinner="dots")
    if "username" not in os.environ or "password" not in os.environ or "client_id" not in os.environ or "client_secret" not in os.environ:
        log.error("One or More Required Credentials are Missing. did you forget to run init()?", extra={"markup": True})
        raise ValueError(4847)
    
    # Is the User Authenticated? Is the Access Token Expired? Is the Refresh Token Expired?
    if "access_token" in os.environ or "refresh_token" in os.environ:
        if datetime.now() < expires_at:
            log.error("Why are you trying to authenticate again? You're already authenticated.")
            log.debug(os.environ)
            return
        if datetime.now() > expires_at and datetime.now() < refresh_expires_at:
            log.error("call refresh() instead of auth(). your access token is expired, but your refresh token is still valid.")
            log.debug(os.environ)
            return
    
    status.start()
    log.info("Authenticating API Client...")

    url = "https://auth.mangadex.org/realms/mangadex/protocol/openid-connect/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "MangaDex-Downloader/v1.0.0dev @lkse"
    }
    data = {
        "grant_type": "password",
        "username": os.environ["username"],
        "password": os.environ["password"],
        "client_id": os.environ["client_id"],
        "client_secret": os.environ["client_secret"]
    }

    try:
        log.debug("Sending Authentication POST...")
        response = requests.post(url, headers=headers, data=data)
        
    except Exception:
        log.exception("An Error Occurred While Authenticating the API Client.")
        raise SystemExit(3284)
    
    if response.status_code == 200:
        log.info("API Client Successfully Authenticated.")
        response = response.json()
        now = datetime.now()
        expires_in = response["expires_in"]
        expires_at = now + timedelta(seconds=expires_in)
        refresh_expires_in = response["refresh_expires_in"]
        refresh_expires_at = now + timedelta(seconds=refresh_expires_in)
        log.debug(f"Access Token Expires At: [bold cyan]{expires_at}[/bold cyan]", extra={"markup": True})
        log.debug(response)
        os.environ["access_token"] = response["access_token"]
        os.environ["refresh_token"] = response["refresh_token"]
    else:
        log.error(f"An Error Occurred While Authenticating the API Client. Status Code: [bold cyan]{response.status_code}[/bold cyan]", extra={"markup": True})
        log.error(response)
        status.stop()
        return 0
    status.stop()
    return 1

def refresh():
    """
    Refreshes the Access Token using the Refresh Token.
    """
    status = console.status("[bold]Refreshing Access Token...[/bold]", spinner="dots")
    if "refresh_token" not in os.environ:
        log.error("Refresh Token Not Found. Did you forget to authenticate?", extra={"markup": True})
        raise ValueError(4847)
    
    # Is the Refresh Token Expired?
    if datetime.now() > refresh_expires_at:
        log.error("Your Refresh Token has Expired. Please Re-Authenticate.", extra={"markup": True})
        return
    
    status.start()
    log.info("Refreshing Access Token...")

    url = "https://auth.mangadex.org/realms/mangadex/protocol/openid-connect/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "MangaDex-Downloader/v1.0.0dev @lkse"
    }
    data = {
        "grant_type": "refresh_token",
        "refresh_token": os.environ["refresh_token"],
        "client_id": os.environ["client_id"],
        "client_secret": os.environ["client_secret"]
    }

    try:
        log.debug("Sending Refresh POST...")
        response = requests.post(url, headers=headers, data=data)
        
    except Exception:
        log.exception("An Error Occurred While Refreshing the Access Token.")
        raise SystemExit(3284)
    
    if response.status_code == 200:
        log.info("Access Token Successfully Refreshed.")
        response = response.json()
        now = datetime.now()
        expires_in = response["expires_in"]
        expires_at = now + timedelta(seconds=expires_in)
        refresh_expires_in = response["refresh_expires_in"]
        refresh_expires_at = now + timedelta(seconds=refresh_expires_in)
        log.debug(f"Access Token Expires At: [bold cyan]{expires_at}[/bold cyan]", extra={"markup": True})
        log.debug(response)
        os.environ["access_token"] = response["access_token"]
        os.environ["refresh_token"] = response["refresh_token"]
    else:
        log.error(f"An Error Occurred While Refreshing the Access Token. Status Code: [bold cyan]{response.status_code}[/bold cyan]", extra={"markup": True})
        log.error(response)
        status.stop()
        return 0
    status.stop() 
    return 1

def fetch_manga(id) -> None:
    """
    Fetches the Manga Details from the MangaDex API.

    Returns:
    - dict: Returns the Manga Details as a dictionary.
    """
    status = console.status("[bold]Fetching Manga Details...[/bold]", spinner="dots")
    status.start()
    log.info("Fetching Manga Details...")

    url = f"https://api.mangadex.org/manga/{id}/feed"
    params = {
        "translatedLanguage[]:" : "en",
        "order[publishAt]" : "asc",
        "limit": 100,
        "offset": 0,
        "includeFuturePublishAt": 0,
        "includeExternalUrl": 0
    }

    headers = {
        "Authorization": f"Bearer {os.environ['access_token']}",
        "User-Agent": "MangaDex-Downloader/v1.0.0dev @lkse"
    }

    try:
        log.debug("Sending Manga GET...")
        response = requests.get(url, headers=headers, params=params)
        
    except Exception:
        log.exception("An Error Occurred While Fetching Manga Details.")
        raise SystemExit(3284)
    
    if response.status_code == 200:
        log.info("Manga Details Successfully Fetched.")
        response = response.json()
        total = response['total']
        # write to file
        with open(f'./data/{id}.json', 'w') as f:
            json.dump(response, f)
        
        if total > 100:
            log.info(f"Fetching {total} Chapters. This may take a while...")
            offset = 100
            while offset < total:
                params['offset'] = offset
                try:
                    log.debug("Sending Manga GET...")
                    log.debug(f"Offset: [bold cyan]{offset}[/bold cyan]", extra={"markup": True})
                    log.debug(f"headers: [bold cyan]{headers}[/bold cyan]", extra={"markup": True})
                    response = requests.get(url, headers=headers, params=params)
                    
                except Exception:
                    log.exception("An Error Occurred While Fetching Manga Details.")
                    return 0 
                
                if response.status_code == 200:
                    with open(f'./data/{id}.json', 'r') as f:
                        log.debug("Reading Existing Data...")
                        data = json.load(f)

                    log.debug("Extending Data...")
                    r = response.json()
                    data['data'].extend(r['data'])

                    with open(f'./data/{id}.json', 'w') as f:
                        log.debug("Writing Extended Data...")   
                        json.dump(data, f)

                    log.info(f"Successfully Fetched {offset}/{total} Chapters.")
                    sleep(3)
            
                if response.status_code == 429:
                    log.warning(f"We've been rate limited. Waiting for 30 seconds...")
                    sleep(30)
                    continue
                
                offset += 100
                continue
        
        log.info("All Chapters Successfully Fetched.")


    else:
        log.error(f"An Error Occurred While Fetching Manga Details. Status Code: [bold cyan]{response.status_code}[/bold cyan]", extra={"markup": True})
        log.error(response)
        status.stop()
        return 0
    status.stop()
    return response

def download_chapters(jsonpath: str) -> None:
    """
    Downloads the Full-Resolution Images from the MangaDex API.

    Parameters:
    - jsonpath (str): The path to the JSON file containing the Manga Details, fetch_managa()

    Returns:
    - None
    """

    #open the path
    with open(jsonpath, 'r') as f:
        data = json.load(f)

    # Strip jsonpath for id
    manga_id = jsonpath.split('/')[-1].split('.')[0]


    chapters = data['data']
    log.info(f"Downloading {len(chapters)} Chapters... this may take a while.")
    for chapter in chapters:
        chapter_id = chapter['id']
        attributes = chapter['attributes']
        chapter_number = attributes['chapter']
        volume_number = attributes['volume']
        chapter_title = attributes['title']
        pages_count = attributes['pages']

        log.info(f"Downloading {pages_count} pages from Volume {volume_number}, Chapter {chapter_number}: '{chapter_title}'...")
        url = f"https://api.mangadex.org/at-home/server/{chapter_id}"
        headers = {
            "Authorization": f"Bearer {os.environ['access_token']}",
            "User-Agent": "MangaDex-Downloader/v1.0.0dev @lkse"
        }

        try:
            log.debug("Sending Chapter GET...")
            response = requests.get(url, headers=headers)
        except Exception:
            log.exception("An Error Occurred While Fetching Chapter Details.")
            return 0
        
        if response.status_code == 200:
            r = response.json()
            base_url = r['baseUrl']
            chapter = r['chapter']
            hash = chapter['hash']
            images = chapter['data']

            for page_number, image in enumerate(images):
                log.info(f"Downloading Page {page_number+1}/{pages_count}...")
                image_url = f"{base_url}/data/{hash}/{image}"
                headers = {
                    "User-Agent": "MangaDex-Downloader/v1.0.0dev @lkse"
                }
                try:
                    log.debug("Sending Image GET...")
                    response = requests.get(image_url, headers=headers)
                    log.debug(response)
                except Exception:
                    log.exception("An Error Occurred While Fetching Image.")
                    return 0
                
                if response.status_code == 200 and response.headers['Content-Type'] == 'image/png':
                    try:
                        os.makedirs(f"./Downloads/{manga_id}/Volume {volume_number}/Chapter {chapter_number} ({chapter_title})", exist_ok=True)
                        with open(f"./Downloads/{manga_id}/Volume {volume_number}/Chapter {chapter_number} ({chapter_title})/{page_number+1}.png", 'wb') as f:
                            f.write(response.content)
                    except Exception:
                        log.exception("An Error Occurred While Writing Image.")
                        return 0
                
                if response.status_code == 429:
                    log.warning(f"We've been rate limited. Waiting for 20 seconds...")
                    sleep(20)
                    continue
                
                if response.status_code != 200:
                    log.error(f"An Error Occurred While Fetching Image. Status Code: [bold cyan]{response.status_code}[/bold cyan]", extra={"markup": True})
                    log.error(response)
                if response.status_code == 200 and response.headers['Content-Type'] != 'image/png':
                    log.error(f"An Error Occurred While Fetching Image. Content-Type: [bold cyan]{response.headers['Content-Type']}[/bold cyan]", extra={"markup": True})
                    log.error(response)



if __name__ == "__main__":
    cls()
    console.rule("MangaDex Downloader v1.0.0 By @lkse",)
    i = init()
    if i:
        a = auth()
        if a:
            id = Prompt.ask("Enter the [italic gold3]MangaDex[/italic gold3] [blink bold italic chartreuse1]Manga ID: [/blink bold italic chartreuse1]")
            fetch_manga(id)
            download_chapters(f'./data/{id}.json')



            


