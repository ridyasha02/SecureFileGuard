import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    messagebox.showinfo("Success", "AES Key generated and saved as 'secret.key'")

def load_key():
    return open("secret.key", "rb").read()

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    with open("private.pem", "wb") as private_file:
        private_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open("public.pem", "wb") as public_file:
        public_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    messagebox.showinfo("Success", "RSA key pair generated and saved as 'private.pem' and 'public.pem'")

def encrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    key = load_key()
    fernet = Fernet(key)
    
    with open(file_path, "rb") as file:
        file_data = file.read()
    
    encrypted_data = fernet.encrypt(file_data)
    with open(file_path + ".enc", "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)
    
    messagebox.showinfo("Success", f"File '{file_path}' encrypted successfully!")

def decrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    key = load_key()
    fernet = Fernet(key)
    
    with open(file_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()
    
    decrypted_data = fernet.decrypt(encrypted_data)
    original_file_path = file_path.replace(".enc", "")
    
    with open(original_file_path, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)
    
    messagebox.showinfo("Success", f"File '{file_path}' decrypted successfully!")

def sign_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    
    with open("private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None
        )
    
    with open(file_path, "rb") as file:
        file_data = file.read()
    
    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    with open(file_path + ".sig", "wb") as sig_file:
        sig_file.write(signature)
    
    messagebox.showinfo("Success", f"File '{file_path}' signed successfully!")

def verify_signature():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    sig_path = file_path + ".sig"
    if not os.path.exists(sig_path):
        messagebox.showerror("Error", "Signature file not found!")
        return
    
    with open("public.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    
    with open(file_path, "rb") as file:
        file_data = file.read()
    
    with open(sig_path, "rb") as sig_file:
        signature = sig_file.read()
    
    try:
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        messagebox.showinfo("Success", "Signature verification successful!")
    except:
        messagebox.showerror("Error", "Signature verification failed!")

root = tk.Tk()
root.title("SecureFileGuard")
root.geometry("500x500")
root.configure(bg="#2C3E50")

button_style = {
    "font": ("Arial", 12, "bold"),
    "fg": "white",
    "bg": "#3498DB",
    "activebackground": "#2980B9",
    "width": 30,
    "height": 2,
    "bd": 3,
    "relief": "raised"
}

label_style = {
    "font": ("Arial", 14, "bold"),
    "fg": "white",
    "bg": "#2C3E50",
    "pady": 10
}

tk.Label(root, text="Secure File Encryption & Decryption", **label_style).pack(pady=10)

tk.Button(root, text="Generate AES Key", command=generate_key, **button_style).pack(pady=5)
tk.Button(root, text="Generate RSA Keys", command=generate_rsa_keys, **button_style).pack(pady=5)
tk.Button(root, text="Encrypt File", command=encrypt_file, **button_style).pack(pady=5)
tk.Button(root, text="Decrypt File", command=decrypt_file, **button_style).pack(pady=5)
tk.Button(root, text="Sign File", command=sign_file, **button_style).pack(pady=5)
tk.Button(root, text="Verify Signature", command=verify_signature, **button_style).pack(pady=5)

tk.Label(root, text="Ensure file security with SecureFileGuard", **label_style).pack(pady=10)
root.mainloop()
