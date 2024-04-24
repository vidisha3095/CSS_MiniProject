from tkinter import Tk, Label, Entry, Button, filedialog, messagebox
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import secrets
from PIL import Image

# Function to pad data for encryption
def pad_data(data):
    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data

# Function to remove padding after decryption
def unpad_data(data):
    unpadder = padding.PKCS7(64).unpadder()
    unpadded_data = unpadder.update(data)
    return unpadded_data + unpadder.finalize()

# Function to generate three random keys
def generate_random_keys():
    return [secrets.token_bytes(8) for _ in range(3)]  # 8 bytes for DES key

# Function to encrypt image using Triple DES
def encrypt_image(image_path, keys):
    with open(image_path, 'rb') as f:
        plaintext = f.read()
    plaintext = pad_data(plaintext)
    
    # Apply Triple DES encryption with three keys
    ciphertext = plaintext
    for key in keys:
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(ciphertext) + encryptor.finalize()
    return ciphertext

# Function to decrypt image using Triple DES
def decrypt_image(encrypted_data, keys):
    # Apply Triple DES decryption with three keys in reverse order
    decrypted_data = encrypted_data
    for key in reversed(keys):
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(decrypted_data) + decryptor.finalize()
    decrypted_data = unpad_data(decrypted_data)
    return decrypted_data

# Function to browse image file
def browse_image():
    file_path = filedialog.askopenfilename()
    entry_image_path.delete(0, 'end')
    entry_image_path.insert(0, file_path)

# Function to generate keys and display them
def generate_and_display_keys():
    keys = generate_random_keys()
    entry_key1.delete(0, 'end')
    entry_key1.insert(0, keys[0].hex())
    entry_key2.delete(0, 'end')
    entry_key2.insert(0, keys[1].hex())
    entry_key3.delete(0, 'end')
    entry_key3.insert(0, keys[2].hex())

# Function to encrypt and display
def encrypt_and_display():
    image_path = entry_image_path.get()
    if not image_path:
        messagebox.showerror("Error", "Please select an image.")
        return
    
    keys = [bytes.fromhex(entry_key1.get()), bytes.fromhex(entry_key2.get()), bytes.fromhex(entry_key3.get())]
    if not all(keys):
        messagebox.showerror("Error", "Please enter three keys.")
        return
    
    encrypted_image = encrypt_image(image_path, keys)
    
    # Save encrypted image as text file
    index = len(os.listdir('.'))  # Generate index number
    encrypted_file_path = save_encrypted_image(encrypted_image, index)
    messagebox.showinfo("Encryption", f"Image encrypted and saved as {encrypted_file_path}")

# Function to decrypt and display
def decrypt_and_display():
    encrypted_text_path = entry_image_path.get()
    if not encrypted_text_path:
        messagebox.showerror("Error", "Please select an encrypted image.")
        return
    
    keys = [bytes.fromhex(entry_key1.get()), bytes.fromhex(entry_key2.get()), bytes.fromhex(entry_key3.get())]
    if not all(keys):
        messagebox.showerror("Error", "Please enter three keys.")
        return
    
    with open(encrypted_text_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_image_data = decrypt_image(encrypted_data, keys)
    
    # Specify the directory to save the decrypted image
    save_directory = "decrypted_images"
    if not os.path.exists(save_directory):
        os.makedirs(save_directory)
    
    # Extract the base name of the encrypted file
    encrypted_filename = os.path.basename(encrypted_text_path)
    # Construct the path for the decrypted file in the specified directory
    decrypted_filename = os.path.join(save_directory, f"decrypted_{encrypted_filename.split('.')[0]}.png")
    with open(decrypted_filename, 'wb') as f:
        f.write(decrypted_image_data)
    messagebox.showinfo("Success", f"Decrypted image saved as {decrypted_filename}")

# Function to save encrypted image as text
def save_encrypted_image(image_data, index):
    filename = f"encrypted_image_{index}.txt"
    with open(filename, 'wb') as f:
        f.write(image_data)
    return filename

# Function to reset entry fields
def reset():
    entry_image_path.delete(0, 'end')
    entry_key1.delete(0, 'end')
    entry_key2.delete(0, 'end')
    entry_key3.delete(0, 'end')

# Create GUI
root = Tk()
root.title("Encryption and Decryption of Image Using Triple DES")

# Define GUI elements
label_image_path = Label(root, text="Image Path:")
label_image_path.grid(row=0, column=0, sticky='e', pady=5)

entry_image_path = Entry(root, width=30)
entry_image_path.grid(row=0, column=1, padx=5, pady=5)

button_browse = Button(root, text="Browse", command=browse_image)
button_browse.grid(row=0, column=2, padx=5, pady=5)

label_key1 = Label(root, text="Key 1:")
label_key1.grid(row=1, column=0, sticky='e', pady=5)

entry_key1 = Entry(root, width=30)
entry_key1.grid(row=1, column=1, padx=5, pady=5)

label_key2 = Label(root, text="Key 2:")
label_key2.grid(row=2, column=0, sticky='e', pady=5)

entry_key2 = Entry(root, width=30)
entry_key2.grid(row=2, column=1, padx=5, pady=5)

label_key3 = Label(root, text="Key 3:")
label_key3.grid(row=3, column=0, sticky='e', pady=5)

entry_key3 = Entry(root, width=30)
entry_key3.grid(row=3, column=1, padx=5, pady=5)

button_generate_keys = Button(root, text="Generate Random Keys", command=generate_and_display_keys)
button_generate_keys.grid(row=1, column=2, rowspan=3, padx=5, pady=5)

button_encrypt = Button(root, text="Encrypt", command=encrypt_and_display, width=15)
button_encrypt.grid(row=4, column=0, pady=5)

button_decrypt = Button(root, text="Decrypt", command=decrypt_and_display, width=15)
button_decrypt.grid(row=4, column=1, pady=5)

button_reset = Button(root, text="Reset", command=reset, width=15)
button_reset.grid(row=4, column=2, pady=5)

button_exit = Button(root, text="Exit", command=root.destroy, width=15)
button_exit.grid(row=5, column=0, columnspan=3, pady=5)

# Set font
font = ("Arial", 10)

# Configure labels and entry widgets with font
label_image_path.config(font=font)
label_key1.config(font=font)
label_key2.config(font=font)
label_key3.config(font=font)
entry_image_path.config(font=font)
entry_key1.config(font=font)
entry_key2.config(font=font)
entry_key3.config(font=font)

root.mainloop()
