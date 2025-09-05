import sqlite3
import pwinput as masked
from rich.console import Console
from rich.prompt import Prompt
import base64
import os
import time
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

console = Console()
con = None
cur = None
current_user_email = None
ph = PasswordHasher()

SALT_SIZE = 16
NONCE_SIZE = 12
ITERATIONS = 200_000
KEY_SIZE = 32

COLOR_MAP = {
    "CYAN": "bright_cyan",
    "YELLOW": "bright_yellow",
    "RED": "bright_red",
    "GREEN": "bright_green",
    "WHITE": "white",
    "MAGENTA": "bright_magenta",
}

def Print(message, color="WHITE", style=""):
    color_code = COLOR_MAP.get(color, "white")
    for char in message:
        console.print(char, style=f"{style} {color_code}", end="")
        time.sleep(0.003)
    console.print("")

def Print_Line(message, color="WHITE", style=""):
    color_code = COLOR_MAP.get(color, "white")
    console.print(message, style=f"{style} {color_code}")

def input_colored(prompt=""):
    return Prompt.ask(f"[bright_cyan]{prompt}[/bright_cyan]")

def pwinput(prompt, mask="*"):
    return masked.pwinput(prompt=prompt, mask=mask)

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(master_password.encode())

def encrypt_password(master_password: str, plaintext: str) -> str:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(salt + nonce + ciphertext).decode()

def decrypt_password(master_password: str, token: str) -> str:
    raw = base64.b64decode(token)
    salt, nonce, ciphertext = raw[:SALT_SIZE], raw[SALT_SIZE:SALT_SIZE+NONCE_SIZE], raw[SALT_SIZE+NONCE_SIZE:]
    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

def connect():
    global con, cur
    con = sqlite3.connect("password_vault.db")
    cur = con.cursor()
    create_tables()

def create_tables():
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            nickname TEXT,
            master_password TEXT
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS password_vault (
            S_no INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            Name_Of_Website TEXT,
            Website_Url TEXT,
            User_Name TEXT,
            Password TEXT,
            FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
        );
    """)
    con.commit()

def insert_row(row_rec, master_pw):
    global current_user_email
    encrypted_password = encrypt_password(master_pw, row_rec[3])
    cur.execute("""
        INSERT INTO password_vault (email, Name_Of_Website, Website_Url, User_Name, Password)
        VALUES (?, ?, ?, ?, ?);
    """, (current_user_email, row_rec[0], row_rec[1], row_rec[2], encrypted_password))
    con.commit()
    Print_Line("Row inserted!", "GREEN", "bold")

def execute_select(query, params=()):
    cur.execute(query, params)
    return cur.fetchall()

def execute_select_and_display(query, master_pw, params=()):
    cur.execute(query, params)
    results = cur.fetchall()
    if not results:
        Print_Line("No saved credentials found.", "RED", "bold")
        return None
    for i in results:
        border = "-" * 70
        Print_Line(border, "WHITE")
        Print_Line(f"S.No       --- {i[0]}", "YELLOW")
        Print_Line(f"Website    --- {i[2]}", "YELLOW")
        Print_Line(f"URL        --- {i[3]}", "CYAN")
        Print_Line(f"Username   --- {i[4]}", "MAGENTA")
        try:
            decrypted_pass = decrypt_password(master_pw, i[5])
        except Exception:
            decrypted_pass = "<decryption failed>"
        Print_Line(f"Password   --- {decrypted_pass}", "GREEN")
        Print_Line(border, "WHITE")

def create_user(email, nickname, master_password):
    hashed_pw = ph.hash(master_password)
    cur.execute("INSERT INTO users VALUES (?, ?, ?);", (email, nickname, hashed_pw))
    con.commit()

def get_user(email):
    cur.execute("SELECT email, nickname, master_password FROM users WHERE email = ?;", (email,))
    return cur.fetchone()

def verify_user(email, master_password):
    row = get_user(email)
    if not row: return False
    try:
        ph.verify(row[2], master_password)
        return True
    except Exception:
        return False

def set_current_user(email):
    global current_user_email
    current_user_email = email

def update(master_pw):
    global current_user_email
    results = execute_select("SELECT * FROM password_vault WHERE email = ?;", (current_user_email,))
    if not results:
        Print_Line("No saved credentials.", "YELLOW")
        return
    Print_Line("Enter S_no of record to update:", "CYAN")
    try:
        s_no = int(input_colored())
    except ValueError:
        Print_Line("Invalid S_no.", "RED")
        return
    Print_Line('''What to update?
    1. Website Name
    2. Website URL
    3. Username
    4. Password''', "MAGENTA", "bold")
    choice = int(input_colored())
    if choice == 1:
        new_val = input_colored("New website name")
        cur.execute("UPDATE password_vault SET Name_Of_Website = ? WHERE S_no = ?;", (new_val, s_no))
    elif choice == 2:
        new_val = input_colored("New URL")
        cur.execute("UPDATE password_vault SET Website_Url = ? WHERE S_no = ?;", (new_val, s_no))
    elif choice == 3:
        new_val = input_colored("New username")
        cur.execute("UPDATE password_vault SET User_Name = ? WHERE S_no = ?;", (new_val, s_no))
    elif choice == 4:
        new_val = pwinput("New password")
        encrypted_pw = encrypt_password(master_pw, new_val)
        cur.execute("UPDATE password_vault SET Password = ? WHERE S_no = ?;", (encrypted_pw, s_no))
    con.commit()
    Print_Line("Record updated!", "GREEN", "bold")

def delete():
    global current_user_email
    Print_Line("Enter S_no of record to delete:", "CYAN")
    try:
        s_no = int(input_colored())
    except ValueError:
        Print_Line("Invalid S_no.", "RED")
        return
    cur.execute("DELETE FROM password_vault WHERE S_no = ?;", (s_no,))
    con.commit()
    Print_Line("Record deleted!", "GREEN", "bold")
