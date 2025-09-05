_**🛡️ Password Manager: Secure Your Digital Life!**_
Welcome to your all-in-one Password Manager—a fast, secure, and intuitive solution for keeping your credentials protected. Built with Python, this project offers state-of-the-art encryption, easy password generation, and an interactive command-line experience powered by Rich formatting.

**Features**
Strong Encryption: Your data is always protected using Argon2 hashing and AES-GCM encryption for vault security.
Smart Password Generator: Instantly create complex, unique passwords and copy them to your clipboard.
Personal Vault: Store, update, view, and delete credentials for all your online accounts in one secure place.
Account System: Supports user registration with secure master password authentication.
Rich CLI Experience: Enjoy colorful prompts, clear instructions, and smooth feedback using Rich Console.

**Getting Started**
Install dependencies:
Copy-paste the following command to your terminal and click enter 
_pip install rich pyperclip pwinput argon2-cffi cryptography_

**Run the application:**

Copy-paste the following command to your terminal and click enter 
_python Main.py_

**How It Works**

Log in or create a new account with a master password.
Generate strong passwords with custom options for length and special characters.
Save credentials (website, username, password) securely in a local, encrypted SQLite database.
Effortlessly retrieve, update, or delete your saved passwords via simple CLI commands.

**Security Highlights**

Master password is safely hashed using Argon2 - a strong encryption.
Each password is encrypted with a unique salt and nonce before saving in the database.
Only decrypted at runtime with your master password—ensuring maximum confidentiality.

**Contributions**

Contributions welcome! Feel free to fork the repository, suggest features, or submit pull requests.

**License**

Licensed under the MIT License.

_Secure your credentials today—your vault awaits!_
