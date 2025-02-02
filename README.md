# 📧 amelis-smime-decrypt

`amelis-smime-decrypt` is a Python script that connects to an IMAP email mailbox, fetches unread S/MIME encrypted emails, decrypts them using a provided private key, and extracts PDF attachments.

## 🚀 Features

✔️ Connects to an IMAP email server<br>
✔️ Fetches unread emails<br>
✔️ Detects and decrypts S/MIME encrypted emails<br>
✔️ Extracts PDF attachments and saves them<br>
✔️ Secure handling of private keys & credentials<br>

## 📦 Installation for usage

Easy.

TODO: This is still necessary to be done.
```bash
pip install amelis-smime-decrypt
```

## 📦 Installation for development

### Install prerequisites
```bash
# install dependencies for building M2Crypto
sudo apt-get install libssl-dev swig python3-dev gcc python3-virtualenv
```

###  Clone the repository

git clone https://github.com/nerdocs/amelis-smime-decrypt.git
cd amelis-smime-decrypt

### Create a virtualenv

```bash
virtualenv .venv
. .venv/bin/activate
```

### Install package and dependencies

Ensure you have Python 3.8+, then run:

```bash
pip install -e .
```

## 🔑 Configuration

### Update Email Credentials

Create an `.env` file (copy the existing `.env.example`).
Edit the SAVE_DIRECTORY, IMAP_SERVER, EMAIL_ACCOUNT, and EMAIL_PASSWORD inside .env:

IMAP_SERVER = "imap.example.com"
EMAIL_ACCOUNT = "your_email@example.com"
EMAIL_PASSWORD = "your_password"


### S/MIME Decryption Keys

Store your private key and certificate in a secure location:

    .../private_key.pem
    .../certificate.pem

Chances are big that your certificate comes encrypted with the more or less deprecated RC2-40-CBC algorithm as `youremail@example.com.p12` file. If this is the case, convert it to a private key and certificate file using:

```bash
MAIL=youremail@example.com
openssl pkcs12 -in ${MAIL}.p12 -out ${MAIL}.crt.pem -clcerts -nokeys -legacy
openssl pkcs12 -in ${MAIL}.p12 -out ${MAIL}.key.pem -nocerts -nodes -legacy
```
You might need to provide the import password for the certificate.

Update PRIVATE_KEY_PATH and CERTIFICATE_PATH in the `.env` file to point to those files.

## 🛠️ Usage

Run the script:

```bash
python amelis-smime-decrypt.py
```

The script will:

    Connect to the given email inbox.
    Fetch unread emails.
    If encrypted, decrypt them using S/MIME.
    Extract PDF attachments and save them to the given attachments folder.

### 📂 Output

All extracted PDFs are saved in the directory you specify in `SAVE_DIRECTORY`.

attachments/
 ├── invoice_123.pdf
 ├── report.pdf

### Security Considerations

    Protect your private key: Do not share private_key.pem.
    Use environment variables for credentials.
    Limit IMAP access to trusted networks.

## 📝 License

This project is licensed under the GPL v3.0 License or later.

## 🤝 Contributing

Pull requests are welcome! Feel free to fork and submit PRs.

## 📧 Support

For issues, please open a [GitHub Issue](https://github.com/nerdocs/amelis-smime-decrypt/issues).