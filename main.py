import tkinter as tk
import customtkinter as ctk
import re
import string
import random

def check_password_strength(password):
    # Initialize strength and recommendations
    strength = "Weak"
    recommendations = []

    # Check length
    if len(password) < 8:
        recommendations.append("Password should be at least 8 characters long.")
    else:
        # Check complexity
        if not re.search(r"[a-z]", password):
            recommendations.append("Include at least one lowercase letter.")
        if not re.search(r"[A-Z]", password):
            recommendations.append("Include at least one uppercase letter.")
        if not re.search(r"[0-9]", password):
            recommendations.append("Include at least one digit.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            recommendations.append("Include at least one special character.")
        
        # Check for common patterns
        common_patterns = ['123456', 'password', 'qwerty', 'abc123']
        if any(pattern in password for pattern in common_patterns):
            recommendations.append("Avoid using common patterns or passwords.")
        
        # Check entropy score
        entropy = len(set(password)) * len(password)
        if entropy < 50:
            recommendations.append("Consider using a more complex password.")

        # Determine strength based on recommendations
        if len(recommendations) == 0:
            strength = "Strong"
        elif len(recommendations) <= 2:
            strength = "Moderate"
    
    return strength, recommendations

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def on_check_password():
    password = password_entry.get()
    strength, recommendations = check_password_strength(password)
    
    strength_label.configure(text=f"Strength: {strength}")
    recommendations_text.set("\n".join(recommendations) if recommendations else "Password is strong.")

def on_generate_password():
    generated_password = generate_password()
    password_entry.delete(0, tk.END)
    password_entry.insert(0, generated_password)
    on_check_password()  # Check the generated password

# Setup CustomTkinter application
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("Password Strength Checker")
app.geometry("500x400")

# Create and place widgets
instructions_label = ctk.CTkLabel(app, text="Enter your password to check its strength and get recommendations:", wraplength=450)
instructions_label.pack(pady=10)

password_entry = ctk.CTkEntry(app, placeholder_text="Enter password")
password_entry.pack(pady=10)

check_button = ctk.CTkButton(app, text="Check Password", command=on_check_password)
check_button.pack(pady=10)

generate_button = ctk.CTkButton(app, text="Generate Password", command=on_generate_password)
generate_button.pack(pady=10)

strength_label = ctk.CTkLabel(app, text="Strength: Not checked yet")
strength_label.pack(pady=10)

recommendations_text = tk.StringVar()
recommendations_label = ctk.CTkLabel(app, textvariable=recommendations_text, wraplength=450)
recommendations_label.pack(pady=10)

app.mainloop()
