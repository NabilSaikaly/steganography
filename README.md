# Python Image Steganography and Communication App (PISCA)

This application is a steganography tool developed in Python. [Steganography](https://en.wikipedia.org/wiki/Steganography) is the practice of concealing a file, message, image, or video within another file, message, image, or video. This application enables two users (User 1 and User 2) to share hidden messages and information within an image file, using encryption for security.

## How It Works / Usage / Pseudocode

User 1 (Encoder):
```
python steganography.py --mode encode --image_path path_to_image --message "secret message" --recipient_email example@gmail.com
```
- User1 provides the application with an image file path, a secret message to conceal within the image, and an email address of the recipient (User2).
- A unique encryption key is generated using Fernet symmetric encryption from the Cryptography library.
- This key is then used to encrypt the provided message and the recipient's email address.
- The script encrypts the message, the recipient email and embeds them in the image as long with the encryption key using the least significant bit (LSB) method of steganography, separating them by null characters for later differentiation.
- A new image is generated with the hidden encrypted message, encrypted recipient email, and the encryption key, ready to be sent to User2.
- Finally, the script then sends the encryption key via email to User2 using Gmail's API. The sent email includes the encryption key, the new encoded photo and the exact time of Encryption.


User 2 (Decoder):
```
python steganography.py --mode decode --image_path path_to_image_with_hidden_data --encryption_key provided_encryption_key
```
- User2 (on a standalone computer) provides the application with an image file path (the image sent from User1) and the encryption key received via email from User1.
- The script fetches the hidden data from the image: the original encryption key, the encrypted message, and the encrypted recipient email.
- It then compares the fetched encryption key with the one provided by User2. If they don't match, the script ends with an error message.
- If the keys match, the script decrypts the message and the recipient email using the encryption key, and displays the decrypted message to User2.
- The script sends an email to the decrypted recipient email stating the decryption key and the exact time of decryption.
- Finally, the script will corrupt the image.

## Requirements
Python 3.6 or higher and the packages mentioned in `requirements.txt`.

Install the necessary packages with:
```
pip install -r requirements.txt
```

Both users should have a `credentials.json` file in their environment for the Google Gmail API to send emails.


[Gmail Developers Workspace/Application API Python Quickstart Guide](https://developers.google.com/gmail/api/quickstart/python)

## Note
This application uses AES encryption and the LSB (Least Significant Bit) method for hiding data in the image. While this script provides a level of security, it might not be sufficient for highly sensitive information. Therefore, use this application with discretion and for educational purposes only.
