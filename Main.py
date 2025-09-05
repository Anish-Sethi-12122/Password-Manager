import random
import string
import sys
import SQL_PASSWORD as db
import pyperclip
import time
from rich.console import Console
from rich.prompt import Prompt
from rich.text import Text

console = Console()
COLOR_MAP = {
    "CYAN": "bright_cyan",
    "YELLOW": "bright_yellow",
    "RED": "bright_red",
    "GREEN": "bright_green",
    "WHITE": "white",
    "MAGENTA": "bright_magenta"
}

master_pw_global = None

def Print_Line(message, color="WHITE", style=""):
    color_code = COLOR_MAP.get(color, "white")
    for char in message:
        console.print(char, style=f"{style} {color_code}", end="")
        time.sleep(0.0269)
    console.print("")

def input_colored(prompt=""):
    return Prompt.ask(f"[bright_cyan]{prompt}[/bright_cyan]")

def generate():
    Print_Line("----- Generate New Password -----", "YELLOW", "bold")
    num = int(input_colored("Enter password length (4-20)", "MAGENTA"))
    num = max(4, min(num, 20))
    include_special = input_colored("Include special characters? (Yes/No)", "MAGENTA").lower().strip() == "yes"
    low = random.choice(string.ascii_lowercase)
    upp = random.choice(string.ascii_uppercase)
    num_1 = str(random.choice(string.digits))
    sym = random.choice("!@#$%&*_?") if include_special else ""
    draft_pass = low + upp + num_1 + sym
    pool = string.ascii_letters + string.digits + ("!@#$%^&*_;:,.<>?" if include_special else "")
    L1 = ''.join(random.choice(pool) for _ in range(num - len(draft_pass)))
    PASSWORD = list(draft_pass + L1)
    random.shuffle(PASSWORD)
    final_pass = ''.join(PASSWORD)
    pyperclip.copy(final_pass)

    Print_Line("Password copied to clipboard!", "GREEN", "bold")
    return final_pass

def log():
    Print_Line("----- Save Password -----", "YELLOW", "bold")
    name = input_colored("Website Name")
    url = input_colored("Website URL")
    user = input_colored("Username")
    Pass = db.pwinput("Password: ")
    db.insert_row((name, url, user, Pass), master_pw_global)

def retrieve():
    Print_Line("----- View Saved Passwords -----", "YELLOW", "bold")
    rows = db.execute_select("SELECT * FROM password_vault WHERE email = ?;", (db.current_user_email,))
    if not rows:
        Print_Line("No saved credentials.", "RED", "bold")
        return
    for r in rows:
        decrypted = db.decrypt_password(master_pw_global, r[5])
        console.print(
            f"[{r[0]}] [bold yellow]{r[2]}[/bold yellow] "
            f"([cyan]{r[3]}[/cyan]) → [magenta]{r[4]}[/magenta] | [green]{decrypted}[/green]"
        )
    if input_colored("Copy a password? (Yes/No)").lower().strip() == "yes":
        try:
            s_no = int(input_colored("Enter S.No"))
        except ValueError:
            Print_Line("Invalid input!", "RED", "bold")
            return
        for r in rows:
            if r[0] == s_no:
                pyperclip.copy(db.decrypt_password(master_pw_global, r[5]))
                Print_Line("Password copied!", "GREEN", "bold")
                return
        Print_Line("Invalid S.No", "RED", "bold")

def main():
    global master_pw_global
    db.connect()
    Print_Line("----- Welcome to the Password Manager -----", "YELLOW", "bold")

    email = input_colored("Enter your Email-ID").strip()
    user = db.get_user(email)

    if user:
        Print_Line(f"Welcome {user[1]}!", "GREEN", "bold")
        while True:
            PASS = db.pwinput("Enter Master Password: ")
            if db.verify_user(email, PASS):
                Print_Line("Authentication successful!", "GREEN", "bold")
                master_pw_global = PASS
                break
            else:
                Print_Line("Incorrect Master Password", "RED", "bold")
    else:
        if input_colored("User not found. Create New Account? (Yes/No)").lower() == "yes":
            nickname = input_colored("Nickname")
            master_pw = db.pwinput("Set Master Password: ")
            db.create_user(email, nickname, master_pw)
            master_pw_global = master_pw
            Print_Line("Account Created!", "GREEN", "bold")
        else:
            Print_Line("Goodbye!", "RED", "bold")
            sys.exit()

    db.set_current_user(email)

    while True:
        Print_Line('''Choose:
  1. Generate password
  2. Save new password
  3. View saved passwords
  4. Update credentials
  5. Delete record
  6. Logout''', "YELLOW", "bold")

        try:
            ch = int(input_colored("Your choice"))
        except ValueError:
            Print_Line("Invalid input", "RED", "bold")
            continue

        if ch == 1:
            Print_Line(generate(), "WHITE")
        elif ch == 2:
            log()
        elif ch == 3:
            retrieve()
        elif ch == 4:
            db.update(master_pw_global)
        elif ch == 5:
            db.delete()
        elif ch == 6:
            Print_Line("Goodbye!", "RED", "bold")
            break
        else:
            Print_Line("Invalid input", "RED", "bold")

main()
