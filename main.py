import os
import random
import time
import base64
import pickle
from cryptography.fernet import Fernet
from PIL import Image
from stegano import lsb
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.mime.image import MIMEImage

# If modifying these SCOPES, delete the file token.pickle.
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def generate_key():
    return Fernet.generate_key()

def encrypt_message(key, message):
    return Fernet(key).encrypt(message)

def decrypt_message(key, encrypted_message):
    return Fernet(key).decrypt(encrypted_message)

def hide_data_in_image(image_path, data):
    return lsb.hide(image_path, data)

def reveal_data_in_image(image_path):
    return lsb.reveal(image_path)

def send_email(to, subject, body, secret_image_path=None):
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    try:
        service = build('gmail', 'v1', credentials=creds)
        message = create_message(to, subject, body)

        if secret_image_path:
            # Attach the image file
            attachment = create_image_attachment(secret_image_path)
            message.attach(attachment)

        raw_message = {'raw': base64.urlsafe_b64encode(message.as_string().encode()).decode()}
        message = service.users().messages().send(userId='me', body=raw_message).execute()
        print("Message Id: %s" % message['id'])
        return message
    except Exception as error:
        print(f"An error occurred: {error}")
        return None

def create_message(to, subject, body):
    message = MIMEMultipart()
    message['to'] = to
    message['subject'] = subject
    message.attach(MIMEText(body, 'plain'))
    return message

def create_image_attachment(file_path):
    with open(file_path, 'rb') as f:
        attachment = MIMEImage(f.read())
        attachment.add_header('Content-Disposition', 'attachment', filename=os.path.basename(file_path))
    return attachment

def send_message(service, user_id, message):
    try:
        message = (service.users().messages().send(userId=user_id, body=message)
                   .execute())
        print('Message Id: %s' % message['id'])
        return message
    except Exception as error:
        print('An error occurred: %s' % error)

def corrupt_image(image_path):
    # Get the size of the original image file
    original_size = os.path.getsize(image_path)

    with open(image_path, "wb") as file:
        # Overwrite the entire file with random bytes
        file.write(bytearray(random.getrandbits(8) for _ in range(original_size)))
        
    print(f"Image corrupted at {image_path}.")


def user1(image_path, message, recipient_email):
    key = generate_key()
    encrypted_message = encrypt_message(key, message.encode())
    encrypted_email = encrypt_message(key, recipient_email.encode())
    data_to_hide = key + b'\0' + encrypted_message + b'\0' + encrypted_email
    secret_image = hide_data_in_image(image_path, data_to_hide.decode())
    secret_image_path = "secret_image.png"
    secret_image.save(secret_image_path)
    send_email(recipient_email, "Encryption Key", f"Your Encryption Key is: {key.decode()}\nTime of Encryption: {time.ctime()}\n", secret_image_path)
    print("Email sent to recipient with encryption key, decryption time and the secret image.")
    
def user2(image_path, user_provided_encryption_key):
    hidden_data = reveal_data_in_image(image_path).encode()
    hidden_key, encrypted_message, encrypted_email = hidden_data.split(b'\0')

    if hidden_key != user_provided_encryption_key.encode():
        print("Provided encryption key is not correct.")
        return

    decrypted_message = decrypt_message(hidden_key, encrypted_message)
    decrypted_email = decrypt_message(hidden_key, encrypted_email)
    
    print("Decrypted message: ", decrypted_message.decode())
    send_email(decrypted_email.decode(), "Decryption Key Used", f"The Encryption key: {hidden_key.decode()} was used to decrypt.\nTime of Decryption: {time.ctime()}\n")
    print("Email sent to recipient stating the decryption key and decryption time.")
    corrupt_image(image_path)
    print("Corrupted the image successfully.")

if __name__ == "__main__":
    user_type = input("Enter user type (1 or 2): ")
    if user_type == "1":
        image_path = input("Enter image path: ")
        message = input("Enter message to hide: ")
        recipient_email = input("Enter recipient email: ")
        user1(image_path, message, recipient_email)
    elif user_type == "2":
        image_path = input("Enter image path: ")
        user_provided_encryption_key = input("Enter provided encryption key: ")
        user2(image_path, user_provided_encryption_key)
    else:
        print("Invalid user type.")
