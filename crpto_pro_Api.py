import os
import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import secrets

class CryptoAPI:
    """A cryptography API supporting AES, RSA, and SHA-256 algorithms."""
    
    def __init__(self):
        """Initialize the CryptoAPI with supported algorithms."""
        self.algorithms = {
            'aes': self._aes_encrypt_decrypt,
            'rsa': self._rsa_encrypt_decrypt,
            'sha256': self._sha256_hash
        }
        # Generate RSA key pair
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

    def _validate_input(self, algorithm: str, key: bytes, data: str) -> None:
        """Validate input parameters to prevent common vulnerabilities."""
        if algorithm.lower() not in self.algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Supported: {list(self.algorithms.keys())}")
        if not data:
            raise ValueError("Input data cannot be empty")
        if algorithm.lower() != 'sha256' and not key:
            raise ValueError("Key cannot be empty for encryption/decryption")

    def _aes_encrypt_decrypt(self, operation: str, key: bytes, data: str) -> str:
        """Handle AES encryption and decryption."""
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes long")
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        
        if operation == "encrypt":
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data.encode()) + padder.finalize()
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            return b64encode(iv + ciphertext).decode()
        else:  # decrypt
            try:
                data_bytes = b64decode(data)
                iv, ciphertext = data_bytes[:16], data_bytes[16:]
                decryptor = cipher.decryptor()
                padded_data = decryptor.update(ciphertext) + decryptor.finalize()
                unpadder = padding.PKCS7(128).unpadder()
                plaintext = unpadder.update(padded_data) + unpadder.finalize()
                return plaintext.decode()
            except Exception as e:
                raise ValueError(f"Decryption failed: {str(e)}")

    def _rsa_encrypt_decrypt(self, operation: str, key: bytes, data: str) -> str:
        """Handle RSA encryption and decryption."""
        try:
            if operation == "encrypt":
                ciphertext = self.rsa_public_key.encrypt(
                    data.encode(),
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                return b64encode(ciphertext).decode()
            else:  # decrypt
                plaintext = self.rsa_private_key.decrypt(
                    b64decode(data),
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                return plaintext.decode()
        except Exception as e:
            raise ValueError(f"RSA {operation} failed: {str(e)}")

    def _sha256_hash(self, operation: str, key: bytes, data: str) -> str:
        """Compute SHA-256 hash of the input data."""
        if operation != "hash":
            raise ValueError("SHA-256 only supports hashing")
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data.encode())
        return digest.finalize().hex()

    def process(self, algorithm: str, operation: str, key: bytes, data: str) -> str:
        """
        Process the input data using the specified algorithm and operation.
        
        Args:
            algorithm (str): The cryptographic algorithm ('aes', 'rsa', 'sha256')
            operation (str): The operation ('encrypt', 'decrypt', 'hash')
            key (bytes): The key for encryption/decryption (ignored for SHA-256)
            data (str): The plaintext or ciphertext input
            
        Returns:
            str: The resulting ciphertext, plaintext, or hash
        """
        self._validate_input(algorithm, key, data)
        return self.algorithms[algorithm.lower()](operation.lower(), key, data)

class CryptoApp:
    """GUI application for the CryptoAPI."""
    
    def __init__(self, root):
        """Initialize the GUI."""
        self.root = root
        self.root.title("CryptoAPI")
        self.root.geometry("600x500")
        self.crypto_api = CryptoAPI()
        self.current_key = None
        self.setup_gui()

    def setup_gui(self):
        """Set up the GUI components."""
        # Algorithm selection
        tk.Label(self.root, text="Select Algorithm:", font=("Arial", 12)).grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.algorithm_var = tk.StringVar(value="aes")
        algorithm_menu = ttk.Combobox(self.root, textvariable=self.algorithm_var, values=["aes", "rsa", "sha256"], state="readonly")
        algorithm_menu.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        algorithm_menu.bind("<<ComboboxSelected>>", self.update_operation_options)

        # Operation selection
        tk.Label(self.root, text="Select Operation:", font=("Arial", 12)).grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.operation_var = tk.StringVar(value="encrypt")
        self.operation_frame = tk.Frame(self.root)
        self.operation_frame.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        tk.Radiobutton(self.operation_frame, text="Encrypt", variable=self.operation_var, value="encrypt").pack(side="left")
        tk.Radiobutton(self.operation_frame, text="Decrypt", variable=self.operation_var, value="decrypt").pack(side="left")
        tk.Radiobutton(self.operation_frame, text="Hash", variable=self.operation_var, value="hash").pack(side="left")

        # Input text
        tk.Label(self.root, text="Input Text:", font=("Arial", 12)).grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.input_text = tk.Text(self.root, height=3, width=50)
        self.input_text.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

        # Key input and generation
        tk.Label(self.root, text="Key (AES only):", font=("Arial", 12)).grid(row=3, column=0, padx=10, pady=5, sticky="w")
        self.key_entry = tk.Entry(self.root, width=50)
        self.key_entry.grid(row=3, column=1, padx=10, pady=5, sticky="ew")
        tk.Button(self.root, text="Generate AES Key", command=self.generate_key).grid(row=4, column=1, padx=10, pady=5, sticky="w")

        # Process button
        tk.Button(self.root, text="Process", command=self.process, font=("Arial", 12), bg="#4CAF50", fg="white").grid(row=5, column=0, columnspan=2, pady=10)

        # Output
        tk.Label(self.root, text="Output:", font=("Arial", 12)).grid(row=6, column=0, padx=10, pady=5, sticky="w")
        self.output_text = tk.Text(self.root, height=5, width=50, state="disabled")
        self.output_text.grid(row=6, column=1, padx=10, pady=5, sticky="ew")

        # Configure grid weights
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(6, weight=1)

        # Initial update of operation options
        self.update_operation_options()

    def generate_key(self):
        """Generate and display a random AES key."""
        self.current_key = secrets.token_bytes(32)
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, b64encode(self.current_key).decode())
        messagebox.showinfo("Key Generated", "A new AES key has been generated and displayed in the key field. Save it securely!")

    def update_operation_options(self, event=None):
        """Update operation options based on selected algorithm."""
        algorithm = self.algorithm_var.get().lower()
        for widget in self.operation_frame.winfo_children():
            widget.destroy()
        
        if algorithm == "sha256":
            tk.Radiobutton(self.operation_frame, text="Hash", variable=self.operation_var, value="hash").pack(side="left")
            self.operation_var.set("hash")
            self.key_entry.configure(state="disabled")
        else:
            tk.Radiobutton(self.operation_frame, text="Encrypt", variable=self.operation_var, value="encrypt").pack(side="left")
            tk.Radiobutton(self.operation_frame, text="Decrypt", variable=self.operation_var, value="decrypt").pack(side="left")
            self.operation_var.set("encrypt")
            self.key_entry.configure(state="normal" if algorithm == "aes" else "disabled")

    def process(self):
        """Process the input using the selected algorithm and operation."""
        algorithm = self.algorithm_var.get()
        operation = self.operation_var.get()
        data = self.input_text.get("1.0", tk.END).strip()
        
        try:
            key = b""
            if algorithm.lower() != "sha256":
                if algorithm.lower() == "aes":
                    if self.key_entry.get():
                        key = b64decode(self.key_entry.get())
                    elif operation == "encrypt":
                        self.generate_key()
                        key = self.current_key
                    else:
                        raise ValueError("Please provide a key for AES decryption")
            
            result = self.crypto_api.process(algorithm, operation, key, data)
            self.output_text.configure(state="normal")
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", result)
            self.output_text.configure(state="disabled")
        
        except Exception as e:
            messagebox.showerror("Error", str(e))

def main():
    """Run the GUI application."""
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()

