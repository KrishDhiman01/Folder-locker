import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import subprocess
from PIL import Image,ImageTk
import webbrowser

# Key storage file
KEY_FILE = "keyfile.key"

# Generate encryption key (Only needed once)
def generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as keyfile:
            keyfile.write(key)

# Load the encryption key
def load_key():
    with open(KEY_FILE, "rb") as keyfile:
        return keyfile.read()

# Encrypt password before storing
def encrypt_password(password):
    cipher = Fernet(load_key())
    return cipher.encrypt(password.encode())

# Decrypt stored password
def decrypt_password(encrypted_password):
    cipher = Fernet(load_key())
    return cipher.decrypt(encrypted_password).decode()

# Lock folder
def lock_folder():
    folder_path = folder_var.get().strip()  # Remove any extra spaces
    password = password_var.get().strip()

    if not folder_path or not password:
        messagebox.showerror("Error", "Please select a folder and enter a password.")
        return

    # Ensure path uses backslashes on Windows
    folder_path = folder_path.replace("/", "\\")
    

    # Check if folder exists
    if not os.path.exists(folder_path):
        messagebox.showerror("Error", "Folder does not exist.")
        return

    try:
        # Encrypt and store password
        enc_password = encrypt_password(password)
        with open(os.path.join(folder_path, "lock.pass"), "wb") as pass_file:
            pass_file.write(enc_password)

        bat_file_path = os.path.join(folder_path, "folder_locked.bat")
        with open(bat_file_path, "w") as bat_file:
            bat_file.write('@echo off\n')
            bat_file.write('echo This folder is locked using ASTRIS Locking System.\n')
            bat_file.write('pause\n')

        # Hide the folder but KEEP IT BROWSABLE
        os.system(f'attrib +h "{folder_path}"')

        # Set permissions to restrict access but allow it to be browsed
        os.system(f'icacls "{folder_path}" /deny Everyone:(D,W)')

        messagebox.showinfo("Success", "Folder Locked Successfully!\nYou can still manually enter the path when unlocking.")
        password_var.set("")
        folder_var.set("")
        folder_label.config(text="The Folder has been locked successfully")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

# Unlock folder
def unlock_folder():
    folder_path = folder_var.get().strip()
    password = password_var.get().strip()

    if not folder_path or not password:
        messagebox.showerror("Error", "Please enter the folder path and password.")
        return

    password_file = os.path.join(folder_path, "lock.pass")

    if not os.path.exists(password_file):
        messagebox.showerror("Error", "This folder is not locked with this program.")
        return

    try:
        # Read and decrypt stored password
        with open(password_file, "rb") as pass_file:
            stored_password = decrypt_password(pass_file.read())

        # Verify password
        if stored_password != password:
            messagebox.showerror("Error", "Incorrect password!")
            return

        # Unhide the folder
        os.system(f'attrib -h "{folder_path}"')

        # Restore folder access
        os.system(f'icacls "{folder_path}" /grant Everyone:F')

        os.system(f'attrib -h -s "{folder_path}"')

        # Remove password file
        os.remove(password_file)

        messagebox.showinfo("Success", "Folder Unlocked Successfully!")
        password_var.set("")
        folder_var.set("")
        folder_label.config(text="The Folder has been Unlocked successfully")


    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

# Open folder in File Explorer
def open_folder(folder_path):
    if os.path.exists(folder_path):
        subprocess.run(["explorer", folder_path])

# Open folder selection dialog
def select_folder():
    folder_path = filedialog.askdirectory()  # Open folder dialog
    if folder_path:  # If a folder was selected
        folder_var.set(folder_path)  # Store only the folder path (no extra text)
        folder_label.config(text=f"Selected Folder: {folder_path}")  # Update label
            

def show_hidden_folders():
    os.system('attrib -h -s /s /d *')
    messagebox.showinfo("Success", "All hidden folders are now visible.")

def linkedin_link():
    url1 = "https://www.linkedin.com/in/krrish-dhiman/"
    webbrowser.get().open(url1)

def github_link():
    url2 = "https://github.com/KrishDhiman01/"
    webbrowser.get().open(url2)

import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageTk

# GUI Setup
root = tk.Tk()
root.title("Folder Locker")
root.geometry("450x430")
root.resizable(False, False)

# Variables
folder_var = tk.StringVar()
password_var = tk.StringVar()


# Create Frame  
title_frame = tk.Frame(root)  
title_frame.pack(pady=10)  

tk.Button(title_frame, text="Linkedin",width=6,height=2,fg="white",bg="blue", borderwidth=0, command=lambda: linkedin_link()).pack(side="left")  

tk.Label(title_frame, text="ASTRIS Folder Locking System", font=("Arial", 18)).pack(side="left")  

tk.Button(title_frame, text="Github",font=("areial", 10),width=8,height=2,fg="white",bg="black", borderwidth=0, command=lambda: github_link()).pack(side="left") 

# Select Folder Button
tk.Button(root, text="Select Folder", command=select_folder, fg="white", bg="grey", width=40, height=2).pack(pady=30)


folder_label = tk.Label(root, text="No folder selected", font=("Arial", 12))
folder_label.pack(pady=5) 

# Enter Password Label and Entry
tk.Label(root, text="Enter Password:", font=("Arial", 14)).pack(pady=5)
tk.Entry(root, textvariable=password_var, width=50, show="*").pack(pady=5)

# Lock and Unlock Buttons
tk.Button(root, text="Lock Folder", font=("Arial", 15), command=lambda: lock_folder(), fg="white", bg="red", width=35, height=1).pack(pady=10)
tk.Button(root, text="Unlock Folder", font=("Arial", 15), command=lambda: unlock_folder(), fg="white", bg="green", width=35, height=1).pack()
tk.Label(root, text="Created By Krish Dhiman", font=("Arial", 10)).pack(side="bottom", pady=10)


# Ensure encryption key is generated
generate_key()

# Run GUI
root.mainloop()
