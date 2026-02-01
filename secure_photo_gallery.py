import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from PIL import Image, ImageTk

# In-memory user storage (for demo purposes)
users = {}
key = os.urandom(32)  # AES-256 key


def register(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    users[username] = hashed_password


def login(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return users.get(username) == hashed_password


def encrypt_photo(file_path):
    with open(file_path, 'rb') as f:
        photo_data = f.read()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(photo_data) + padder.finalize()

    encrypted_photo = iv + encryptor.update(padded_data) + encryptor.finalize()
    encrypted_file_path = file_path + ".enc"

    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_photo)

    return encrypted_file_path


def decrypt_photo(encrypted_file_path):
    with open(encrypted_file_path, 'rb') as f:
        encrypted_photo = f.read()

    iv = encrypted_photo[:16]
    encrypted_data = encrypted_photo[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    decrypted_file_path = encrypted_file_path.replace(".enc", "_decrypted.jpg")
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)

    return decrypted_file_path


class PhotoGalleryApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Photo Gallery")
        self.root.geometry("500x600")
        self.root.configure(bg="#f0f0f0")

        self.logged_in_user = None

        # Create frames
        self.frame_login = tk.Frame(self.root, bg="#f0f0f0", padx=10, pady=10)
        self.frame_options = tk.Frame(self.root, bg="#f0f0f0", padx=10, pady=10)
        self.frame_image = tk.Frame(self.root, bg="#f0f0f0", padx=10, pady=10)

        self.create_login_widgets()

    def create_login_widgets(self):
        tk.Label(self.frame_login, text="Username:", bg="#f0f0f0").grid(row=0, column=0, sticky=tk.W)
        self.username_entry = tk.Entry(self.frame_login)
        self.username_entry.grid(row=0, column=1)

        tk.Label(self.frame_login, text="Password:", bg="#f0f0f0").grid(row=1, column=0, sticky=tk.W)
        self.password_entry = tk.Entry(self.frame_login, show="*")
        self.password_entry.grid(row=1, column=1)

        self.login_button = tk.Button(self.frame_login, text="Login", command=self.login, bg="#4CAF50", fg="white")
        self.login_button.grid(row=2, column=0, pady=10)

        self.register_button = tk.Button(self.frame_login, text="Register", command=self.register, bg="#2196F3",
                                         fg="white")
        self.register_button.grid(row=2, column=1, pady=10)

        self.frame_login.pack(pady=20)

    def show_user_options(self):
        self.frame_login.pack_forget()  # Hide login frame
        self.create_option_widgets()  # Create option widgets
        self.frame_options.pack(pady=20)

    def create_option_widgets(self):
        self.upload_button = tk.Button(self.frame_options, text="Upload Photo", command=self.upload_photo, bg="#FFC107",
                                       fg="black")
        self.upload_button.grid(row=0, column=0, padx=20, pady=10)

        self.decrypt_button = tk.Button(self.frame_options, text="Decrypt Photo", command=self.decrypt_photo,
                                        bg="#FF5722", fg="white")
        self.decrypt_button.grid(row=0, column=1, padx=20, pady=10)

        self.frame_image.pack(pady=20)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if login(username, password):
            self.logged_in_user = username
            messagebox.showinfo("Login", "Login successful!")
            self.show_user_options()
        else:
            messagebox.showerror("Login", "Invalid credentials.")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username not in users:
            register(username, password)
            messagebox.showinfo("Register", "User registered successfully!")
        else:
            messagebox.showerror("Register", "Username already exists.")

    def upload_photo(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            encrypted_path = encrypt_photo(file_path)
            messagebox.showinfo("Upload", f"Photo encrypted and saved as {encrypted_path}")

    def decrypt_photo(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            decrypted_path = decrypt_photo(file_path)
            messagebox.showinfo("Decrypt", f"Photo decrypted and saved as {decrypted_path}")
            self.show_image(decrypted_path)  # Call to show the image

    def show_image(self, image_path):
        # Open the image and convert it to a format Tkinter can use
        img = Image.open(image_path)
        img.thumbnail((400, 400))  # Resize the image to fit in the window
        img_tk = ImageTk.PhotoImage(img)

        # Create a label to display the image
        if hasattr(self, 'image_label'):
            self.image_label.destroy()  # Remove the previous image if it exists

        self.image_label = tk.Label(self.frame_image, image=img_tk)
        self.image_label.image = img_tk  # Keep a reference to avoid garbage collection
        self.image_label.grid(row=0, column=0, columnspan=2)  # Position it below the buttons


if __name__ == "__main__":
    root = tk.Tk()
    app = PhotoGalleryApp(root)
    root.mainloop()