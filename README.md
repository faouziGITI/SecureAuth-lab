# 💀 SKULL VAULT

**A password security and management application developed by Faouzi and Cerbah.**

SKULL VAULT is a Python desktop application designed to help users generate, evaluate, and securely manage passwords. It includes password-strength analysis, encrypted password storage, and an optional AI-powered security coach.

## ✨ Features

- **Password Strength Checker** — Evaluates password strength and identifies common passwords, predictable sequences, and patterns.
- **AI Security Coach** — Provides additional password-security feedback using an AI API.
- **Secure Password Vault** — Stores passwords in an encrypted local vault.
- **Password Generator** — Generates random passwords and passphrases.
- **Vault Security Audit** — Helps identify reused passwords.
- **Automatic Clipboard Clearing** — Clears copied passwords after a timeout.
- **Automatic Vault Locking** — Locks the vault after inactivity.
- **Master Password Management** — Supports changing the vault's master password.

## 🛠️ Technologies

- Python
- Tkinter — graphical user interface
- Cryptography — encryption and key derivation
- AI API — optional AI-powered password-security analysis

## 📋 Requirements

- Python 3.10 or a compatible version
- pip
- An internet connection for the optional AI feature
- A valid API key from the AI provider configured in the application

## 🚀 Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/faouziGITI/SecureAuth-lab.git
   ```

2. Enter the project directory:

   ```bash
   cd SecureAuth-lab
   ```

3. Install the required dependency:

   ```bash
   python -m pip install cryptography
   ```

4. Run the application:

   ```bash
   python app.py
   ```

Install any additional dependencies required by the version of the application you are using.

## 🤖 Configuring the AI API Key

The AI coach in the password strength checker requires a valid API key from the AI provider supported by the application's current implementation.

1. Create an account with the supported AI provider.
2. Generate an API key through the provider's official developer platform.
3. Configure the key using the application's API-key input, if available, or the environment variable expected by the code.
4. Open the password strength checker and use its AI analysis feature.

**Important:** An API key is a secret credential. Never publish it in this repository, place it directly in source code, or share it publicly. API usage may have limits or incur charges depending on the provider and account.

The AI integration must be configured for the provider's API endpoint, model, and request format. A key from a different provider will not work automatically without the appropriate code changes.

## 🔐 Security Notes

- Use a strong, unique master password.
- Keep backups of important vault data in a secure location.
- Never commit API keys, private configuration files, or your personal vault data to GitHub.
- Test the application with sample passwords rather than real passwords when using external AI services.
- Review the AI provider's privacy policy and usage terms before sending security-related information.

## 👨‍💻 Developers

**Developed by Faouzi and Cerbah.**

## ⚠️ Disclaimer

This project is intended for educational and personal password-security management purposes. No application can guarantee absolute security. Keep the software and its dependencies updated, and use it responsibly.
