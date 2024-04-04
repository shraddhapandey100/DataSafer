import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
from tkinter import *
from PIL import Image, ImageTk
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Generate a random key
def generate_random_key():
    key = os.urandom(32)
    return key

# Encrypt a file with a key
def encrypt_file(file_path, key):
    try:
        # Generate a random initialization vector (IV)
        iv = os.urandom(16)
        print(iv)
        # Create a cipher object
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()

        # Read the file content
        with open(file_path, 'rb') as file:
            file_data = file.read()

        # Encrypt the file content
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()
       
        # Create a new file with ".enc" extension
        encrypted_file_path = file_path + '.aes'
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(iv + encrypted_data)

        return encrypted_file_path
    except Exception as e:
        messagebox.showerror("Encryption Error", f"An error occurred: {str(e)}")
        return None

# Decrypt a file with a key
def decrypt_file(encrypted_file_path, key):
    try:
        # Read the encrypted file
        with open(encrypted_file_path, 'rb') as encrypted_file:
            file_data = encrypted_file.read()

        # Extract IV from the file data
        iv = file_data[:16]
        encrypted_data = file_data[16:]

        # Create a cipher object
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()

        # Decrypt the file content
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove the '.enc' extension from the original file name
        decrypted_file_path = encrypted_file_path[:-4]

        # Write the decrypted data to a new file
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        return decrypted_file_path
    except Exception as e:
        messagebox.showerror("Decryption Error", f"An error occurred: {str(e)}")
        return None

# Create the main application window
root = tk.Tk()
root.title("File Encryption and Decryption GUI")
root.geometry("1000x600+150+120")
root.minsize(1000, 600)
root.maxsize(1000, 600)


image = Image.open("D:\\2ndProject\\DataSafer\\logo.jpg")
resize_image = image.resize((950, 600))
photo = ImageTk.PhotoImage(image)
img = ImageTk.PhotoImage(resize_image)

label2 = Label(image=img)
label2.pack()
label = Label(root, text="DataSafer", relief="solid", fg="black", bg="cyan", font=("arial", 30, "bold"))
label.place(x=390, y=30)

def exit1():
    exit()

# Function to perform encryption and display the key
def encrypt_and_display_key():
    # Generate a random key
    key = generate_random_key()
    print(key)
    
    # Specify the path to the file you want to encrypt
    input_file_path = filedialog.askopenfilename(title="Select a file to encrypt")
    if not input_file_path:
        return

    # Encrypt the file
    encrypted_file_path = encrypt_file(input_file_path, key)

    if encrypted_file_path:
        messagebox.showinfo("Encryption Successful", f"File encrypted and saved as '{encrypted_file_path}'\nEncryption Key: {base64.b64encode(key).decode()}")
        En_Key = 'Key_Data.txt'
        with open(En_Key, 'wb') as encrypted_file:  
            encoded_key = base64.b64encode(key)
            encrypted_file.write(encoded_key)
         
        # Save the encryption key to a Notepad file
        key_file_path = filedialog.asksaveasfilename(title="Save Encryption Key", defaultextension=".txt")
        if key_file_path:
            with open(key_file_path, 'wb') as key_file:
                key_file.write(key)

# Function to decrypt a file using a provided key
def decrypt_using_key():
    # Specify the path to the encrypted file
    encrypted_file_path = filedialog.askopenfilename(title="Select an encrypted file to decrypt")
    if not encrypted_file_path:
        return

    # Prompt the user to enter the decryption key
    custom_key = simpledialog.askstring("Decryption Key", "Enter the decryption key:")
    if not custom_key:
        messagebox.showwarning("Decryption Key", "Please enter the decryption key.")
        return

    try:
        # Ensure the key is 32 bytes
        if len(custom_key) != 44:
            raise ValueError("Invalid key length")

        # Convert the custom key from base64
        key = base64.b64decode(custom_key)
        print(key)

        # Decrypt the file
        decrypted_file_path = decrypt_file(encrypted_file_path, key)

        if decrypted_file_path:
            messagebox.showinfo("Decryption Successful", f"File decrypted and saved as '{decrypted_file_path}'")

    except Exception as e:
        messagebox.showerror("Decryption Error", f"An error occurred: {str(e)}")

# Create buttons for file encryption, decryption, and key display
button = Button(root, text="Encrypt File and Display Key", relief="solid", fg="white", bg="Green",
                font=("yellow", 16, "bold"),
                command=encrypt_and_display_key)
button.place(x=60, y=515)

button = Button(root, text="Decrypt File with Key", relief="solid", fg="white", bg="red",
                font=("arial", 16, "bold"),
                command=decrypt_using_key)
button.place(x=500, y=515)

button = Button(root, text="Quit", relief="solid", fg="white", bg="Green", font=("arial", 16, "bold"),
                command=exit1)
button.place(x=835, y=515)

# Run the main event loop
root.mainloop()
