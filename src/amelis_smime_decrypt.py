import logging
import os
import imaplib
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

from dotenv import load_dotenv
from M2Crypto import BIO, SMIME, X509, EVP

load_dotenv()

logger = logging.getLogger(__file__)

# Email credentials and server details
IMAP_SERVER = os.getenv("IMAP_SERVER")
IMAP_PORT = 993
EMAIL_ACCOUNT = os.getenv("EMAIL_ACCOUNT")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

SAVE_DIRECTORY = os.getenv("SAVE_DIRECTORY")

# S/MIME decryption keys
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH")
CERTIFICATE_PATH = os.getenv("CERTIFICATE_PATH")


def connect_to_mailbox() -> imaplib.IMAP4_SSL | None:
    """Connect to the IMAP mailbox and return the connection."""
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        # mail.starttls()
        mail.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
        mail.select("inbox")
        return mail
    except Exception as e:
        logger.critical(f"Error connecting to mailbox: {e}")
        return None


def fetch_unread_mails(
    mail: imaplib.IMAP4, subject_keyword: str, only_unseen: bool = False
) -> list[str]:
    """Fetch unread emails that contain a specific keyword in the subject."""
    # Construct the search criteria (e.g., "UNSEEN SUBJECT 'keyword'")
    unseen = "UNSEEN " if only_unseen else ""

    search_criteria = f'({unseen}SUBJECT "{subject_keyword}")'
    status, messages = mail.search(None, search_criteria)
    if status != "OK":
        return []

    email_ids = messages[0].decode().split()
    return email_ids


def load_smime_keys():
    """Load S/MIME private key and certificate."""
    smime = SMIME.SMIME()
    smime.load_key(PRIVATE_KEY_PATH, CERTIFICATE_PATH)
    return smime


# def extract_smime_attachment(raw_email):
#     """Extract the smime.p7m attachment from an email."""
#     msg = BytesParser(policy=policy.default).parsebytes(raw_email)
#
#     for part in msg.walk():
#         content_type = part.get_content_type()
#         print(f"🔹 Content type: {content_type}")
#         # # Some email clients use application/x-pkcs7-mime instead
#         # if content_type in ["application/pkcs7-mime", "application/x-pkcs7-mime"]:
#         #     print("🔹 Found S/MIME Encrypted Attachment (smime.p7m)")
#         #     payload = part.get_payload(decode=True)  # Auto-decodes Base64
#         #     return payload
#
#         content_disposition = part.get("Content-Disposition", "")
#         if "attachment" in content_disposition and "smime.p7m" in content_disposition:
#             logger.debug("🔹 Found S/MIME Encrypted Attachment: smime.p7m")
#             return part.get_payload(decode=True)  # Auto-decodes Base64
#
#     print("❌ No S/MIME attachment found.")
#     return None


def decrypt_smime(encrypted_data):
    """Decrypt an S/MIME encrypted email using M2Crypto."""
    try:
        smime = load_smime_keys()

        logger.debug(f"🔹 Encrypted data length: {len(encrypted_data)} bytes")
        logger.debug(f"🔹 First 100 bytes of encrypted data: {encrypted_data[:100]}")

        bio = BIO.MemoryBuffer(encrypted_data)

        # TODO: Check if the data is in the correct format
        try:
            p7, _data = SMIME.smime_load_pkcs7_bio(bio)
        except SMIME.SMIME_Error as e:
            logger.error(f"SMIME_Error occurred: {e}")
            return None

        decrypted_bio = smime.decrypt(p7)

        return decrypted_bio
    except Exception as e:
        logger.error(f"❌ Decryption failed: {e}")
        return None


def process_smime_attachment_email(msg: EmailMessage) -> None:
    """Extract and decrypt S/MIME email attachment (smime.p7m)."""

    for part in msg.walk():
        decoded_payload = part.get_payload(decode=True)  # .decode("iso8859")

        logger.debug(f"Attachment size: {len(decoded_payload)} bytes")
        logger.debug(f"🔹 First 100 bytes of attachment: {decoded_payload[:100]}")

        decrypted_content = decrypt_smime(decoded_payload)
        if decrypted_content:
            logger.info("✅ Successfully decrypted attachment email:")
            # TODO: save attachment to output directory
            # TODO: name output file after patient name
            # For example, save it or extract further attachments
        else:
            logger.error("❌ Attachment email decryption failed.")
        return

    logger.error("❌ No valid S/MIME attachment found.")


def process_email(mail: imaplib.IMAP4_SSL, email_id: str) -> None:
    """Fetch, decrypt, and extract attachments from an email."""

    status, msg_data = mail.fetch(email_id, "(RFC822)")
    if status != "OK":
        logger.error(f"Failed to fetch email {email_id}")
        return

    raw_email: bytes = msg_data[0][1]  # noqa
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw_email)
    logger.info(f"Processing Mail: {msg['Subject']}")
    if msg.get_content_type() == "application/pkcs7-mime" and  msg.is_attachment():
        # we know now that the whole mail is an attachment
        process_smime_attachment_email(msg)  # , part.get_filename())

    #     process_inline_encrypted_email(msg)

    # DEBUG: restore "unseen" status
    mail.store(email_id, "-FLAGS", "\\Seen")


def check_key_and_cert(private_key_path, certificate_path):
    """
    Check if the private key and certificate are valid and match.

    :param private_key_path: Path to the private key file
    :param certificate_path: Path to the certificate file
    :return: True if valid, False otherwise
    """
    try:
        # Check if files exist
        if not os.path.exists(private_key_path):
            logger.critical(f"Private key file '{private_key_path}' does not exist.")
            return False
        if not os.path.exists(  certificate_path):
            print(os.getcwd())
            logger.critical(f"Certificate file '{certificate_path}' does not exist.")
            return False

        # Load private key
        pkey = EVP.load_key(private_key_path)
        if not pkey:
            logger.critical("Failed to load private key.")
            return False

        # Load certificate
        cert = X509.load_cert(certificate_path)
        if not cert:
            logger.critical("Failed to load certificate.")
            return False

        # Check if the private key matches the certificate
        cert_pubkey = cert.get_pubkey()
        cert_rsa = cert_pubkey.get_rsa()
        pkey_rsa = pkey.get_rsa()

        if cert_rsa.e != pkey_rsa.e or cert_rsa.n != pkey_rsa.n:
            logger.critical("Private key does not match the certificate.")
            return False

        # Check certificate expiration
        not_before = cert.get_not_before().get_datetime().replace(tzinfo=None)
        not_after = cert.get_not_after().get_datetime().replace(tzinfo=None)
        now = datetime.now()

        if now < not_before:
            logger.critical("Certificate is not yet valid.")
            return False
        if now > not_after:
            logger.critical("Certificate has expired.")
            return False

        return True

    except Exception as e:
        logger.critical(f"Error checking key and certificate: {e}")
        return False


def decrypt_smime_data(encrypted_data, private_key_path, certificate_path):
    """
    Decrypt S/MIME encrypted data.

    :param encrypted_data: Bytes object containing the S/MIME encrypted data
    :param private_key_path: Path to the private key file
    :param certificate_path: Path to the certificate file
    :return: Decrypted data as bytes, or None if decryption fails
    """
    try:
        # Initialize SMIME object
        smime = SMIME.SMIME()

        # Load private key and certificate
        smime.load_key(private_key_path, certificate_path)

        # Create a BIO buffer from the encrypted data
        in_bio = BIO.MemoryBuffer(encrypted_data)

        # Load the PKCS7 object from the input buffer
        p7, _ = SMIME.smime_load_pkcs7_bio(in_bio)

        # Decrypt the PKCS7 object
        out_bio = smime.decrypt(p7)

        # Read the decrypted data from the output buffer
        decrypted_data = out_bio.read()

        return decrypted_data

    except Exception as e:
        logger.critical(f"Decryption failed: {e}")
        return None


def main():

    if not check_key_and_cert(PRIVATE_KEY_PATH, CERTIFICATE_PATH):
        return

    if not os.path.exists(SAVE_DIRECTORY):
        os.makedirs(SAVE_DIRECTORY)

    mail = connect_to_mailbox()
    if not mail:
        return

    email_ids = fetch_unread_mails(mail, "Auftrag")
    if not email_ids:
        logger.info("No emails found.")
        return

    for email_id in email_ids:
        process_email(mail, email_id)

    mail.logout()


if __name__ == "__main__":
    main()
