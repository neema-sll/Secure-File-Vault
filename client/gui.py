"""
Graphical User Interface for Secure File Vault
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
from client import AuthClient
from encryptor import FileEncryptor

class LoginWindow:
    def __init__(self):
        self.client = AuthClient()
        self.window = tk.Tk()
        self.window.title("Secure File Vault - Login")
        self.window.geometry("400x450")
        self.window.resizable(False, False)
        
        # Center window
        self.center_window()
        
        # Title
        tk.Label(self.window, text="🔐 SECURE FILE VAULT", 
                font=('Arial', 18, 'bold'), fg='blue').pack(pady=30)
        
        # Notebook
        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(expand=True, fill='both', padx=20, pady=10)
        
        # Login tab
        self.login_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.login_frame, text='Login')
        self.create_login_tab()
        
        # Register tab
        self.register_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.register_frame, text='Register')
        self.create_register_tab()
        
        # Status
        self.status = tk.Label(self.window, text="", fg='red')
        self.status.pack(pady=10)
    
    def center_window(self):
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_login_tab(self):
        tk.Label(self.login_frame, text="Username:", font=('Arial', 12)).pack(pady=10)
        self.login_user = tk.Entry(self.login_frame, width=30, font=('Arial', 12))
        self.login_user.pack(pady=5)
        
        tk.Label(self.login_frame, text="Password:", font=('Arial', 12)).pack(pady=10)
        self.login_pass = tk.Entry(self.login_frame, width=30, font=('Arial', 12), show='*')
        self.login_pass.pack(pady=5)
        
        tk.Button(self.login_frame, text="LOGIN", command=self.login,
                 bg='blue', fg='white', font=('Arial', 12, 'bold'),
                 width=20, height=2).pack(pady=30)
        
        self.login_pass.bind('<Return>', lambda e: self.login())
    
    def create_register_tab(self):
        tk.Label(self.register_frame, text="Username:", font=('Arial', 12)).pack(pady=5)
        self.reg_user = tk.Entry(self.register_frame, width=30, font=('Arial', 12))
        self.reg_user.pack(pady=5)
        
        tk.Label(self.register_frame, text="Password:", font=('Arial', 12)).pack(pady=5)
        self.reg_pass = tk.Entry(self.register_frame, width=30, font=('Arial', 12), show='*')
        self.reg_pass.pack(pady=5)
        
        tk.Label(self.register_frame, text="Confirm:", font=('Arial', 12)).pack(pady=5)
        self.reg_confirm = tk.Entry(self.register_frame, width=30, font=('Arial', 12), show='*')
        self.reg_confirm.pack(pady=5)
        
        tk.Button(self.register_frame, text="REGISTER", command=self.register,
                 bg='green', fg='white', font=('Arial', 12, 'bold'),
                 width=20, height=2).pack(pady=20)
    
    def login(self):
        username = self.login_user.get().strip()
        password = self.login_pass.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Enter username and password")
            return
        
        self.status.config(text="Logging in...", fg='blue')
        
        def do_login():
            response = self.client.login(username, password)
            if response['status'] == 'success':
                self.window.after(0, lambda: self.login_success(username))
            else:
                self.window.after(0, lambda: messagebox.showerror("Error", response['message']))
                self.window.after(0, lambda: self.status.config(text=""))
        
        threading.Thread(target=do_login, daemon=True).start()
    
    def register(self):
        username = self.reg_user.get().strip()
        password = self.reg_pass.get()
        confirm = self.reg_confirm.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Fill all fields")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords don't match")
            return
        
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters")
            return
        
        self.status.config(text="Registering...", fg='blue')
        
        def do_register():
            response = self.client.register(username, password)
            if response['status'] == 'success':
                self.window.after(0, lambda: messagebox.showinfo("Success", "Registration successful!"))
                self.window.after(0, lambda: self.login_user.insert(0, username))
                self.window.after(0, lambda: self.notebook.select(0))
            else:
                self.window.after(0, lambda: messagebox.showerror("Error", response['message']))
            self.window.after(0, lambda: self.status.config(text=""))
        
        threading.Thread(target=do_register, daemon=True).start()
    
    def login_success(self, username):
        self.window.destroy()
        main = MainWindow(username)
        main.run()
    
    def run(self):
        self.window.mainloop()


class MainWindow:
    def __init__(self, username):
        self.username = username
        self.encryptor = FileEncryptor()
        
        self.window = tk.Tk()
        self.window.title(f"Secure File Vault - {username}")
        self.window.geometry("600x500")
        
        self.create_widgets()
    
    def create_widgets(self):
        # Title
        tk.Label(self.window, text=f"Welcome, {self.username}!", 
                font=('Arial', 16, 'bold')).pack(pady=20)
        
        # Main frame
        main_frame = tk.Frame(self.window)
        main_frame.pack(expand=True, fill='both', padx=20, pady=10)
        
        # Encrypt section
        encrypt_frame = tk.LabelFrame(main_frame, text="Encrypt File", font=('Arial', 12, 'bold'))
        encrypt_frame.pack(fill='x', pady=10)
        
        tk.Button(encrypt_frame, text="Select File to Encrypt", 
                 command=self.encrypt_file,
                 bg='blue', fg='white', width=20).pack(pady=10)
        
        # Decrypt section
        decrypt_frame = tk.LabelFrame(main_frame, text="Decrypt File", font=('Arial', 12, 'bold'))
        decrypt_frame.pack(fill='x', pady=10)
        
        tk.Button(decrypt_frame, text="Select File to Decrypt", 
                 command=self.decrypt_file,
                 bg='green', fg='white', width=20).pack(pady=10)
        
        # Text encryption section
        text_frame = tk.LabelFrame(main_frame, text="Encrypt/Decrypt Text", font=('Arial', 12, 'bold'))
        text_frame.pack(fill='both', expand=True, pady=10)
        
        tk.Label(text_frame, text="Enter text:").pack(pady=5)
        self.text_input = tk.Text(text_frame, height=5)
        self.text_input.pack(fill='x', padx=10, pady=5)
        
        tk.Label(text_frame, text="Password:").pack(pady=5)
        self.text_pass = tk.Entry(text_frame, show='*')
        self.text_pass.pack(fill='x', padx=10, pady=5)
        
        button_frame = tk.Frame(text_frame)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Encrypt Text", command=self.encrypt_text,
                 bg='blue', fg='white').pack(side='left', padx=5)
        
        tk.Button(button_frame, text="Decrypt Text", command=self.decrypt_text,
                 bg='green', fg='white').pack(side='left', padx=5)
        
        # Result area
        self.result_text = tk.Text(main_frame, height=4, state='disabled')
        self.result_text.pack(fill='x', pady=10)
        
        # Logout button
        tk.Button(self.window, text="Logout", command=self.logout,
                 bg='red', fg='white').pack(pady=10)
    
    def encrypt_file(self):
        password = self.get_password("Enter password for encryption:")
        if not password:
            return
        
        file = filedialog.askopenfilename(title="Select file to encrypt")
        if not file:
            return
        
        output = file + '.encrypted'
        
        def do_encrypt():
            success, message = self.encryptor.encrypt_file(file, output, password)
            if success:
                self.window.after(0, lambda: messagebox.showinfo("Success", 
                                   f"File encrypted successfully!\nSaved as: {output}"))
            else:
                self.window.after(0, lambda: messagebox.showerror("Error", message))
        
        threading.Thread(target=do_encrypt, daemon=True).start()
    
    def decrypt_file(self):
        password = self.get_password("Enter password for decryption:")
        if not password:
            return
        
        file = filedialog.askopenfilename(title="Select file to decrypt", 
                                          filetypes=[("Encrypted files", "*.encrypted")])
        if not file:
            return
        
        output = file.replace('.encrypted', '.decrypted')
        
        def do_decrypt():
            success, message = self.encryptor.decrypt_file(file, output, password)
            if success:
                self.window.after(0, lambda: messagebox.showinfo("Success", 
                                   f"File decrypted successfully!\nSaved as: {output}"))
            else:
                self.window.after(0, lambda: messagebox.showerror("Error", message))
        
        threading.Thread(target=do_decrypt, daemon=True).start()
    
    def encrypt_text(self):
        text = self.text_input.get(1.0, tk.END).strip()
        password = self.text_pass.get()
        
        if not text or not password:
            messagebox.showerror("Error", "Enter text and password")
            return
        
        success, result = self.encryptor.encrypt_text(text, password)
        if success:
            self.result_text.config(state='normal')
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(1.0, result)
            self.result_text.config(state='disabled')
            messagebox.showinfo("Success", "Text encrypted!")
        else:
            messagebox.showerror("Error", result)
    
    def decrypt_text(self):
        encrypted = self.result_text.get(1.0, tk.END).strip()
        password = self.text_pass.get()
        
        if not encrypted or not password:
            messagebox.showerror("Error", "Enter encrypted text and password")
            return
        
        success, result = self.encryptor.decrypt_text(encrypted, password)
        if success:
            self.text_input.delete(1.0, tk.END)
            self.text_input.insert(1.0, result)
            messagebox.showinfo("Success", "Text decrypted!")
        else:
            messagebox.showerror("Error", result)
    
    def get_password(self, prompt):
        """Simple password dialog"""
        dialog = tk.Toplevel(self.window)
        dialog.title("Password")
        dialog.geometry("300x150")
        dialog.transient(self.window)
        dialog.grab_set()
        
        tk.Label(dialog, text=prompt).pack(pady=10)
        password = tk.Entry(dialog, show='*')
        password.pack(pady=10)
        
        result = []
        
        def submit():
            result.append(password.get())
            dialog.destroy()
        
        tk.Button(dialog, text="OK", command=submit).pack()
        password.focus()
        
        self.window.wait_window(dialog)
        return result[0] if result else None
    
    def logout(self):
        if messagebox.askyesno("Confirm", "Logout?"):
            self.window.destroy()
            LoginWindow().run()
    
    def run(self):
        self.window.mainloop()


if __name__ == "__main__":
    # Check if server is running
    import socket
    try:
        s = socket.socket()
        s.connect(('localhost', 8888))
        s.close()
        LoginWindow().run()
    except:
        messagebox.showerror("Error", "Auth server not running!\nStart server first.")