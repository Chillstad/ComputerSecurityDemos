import bcrypt
from getpass import getpass
import sqlite3
from cryptography.fernet import Fernet
import secrets
import string

def print_step(message):
    """Helper function to visualize steps"""
    print(f"\n\033[1;34m[STEP] {message}\033[0m")

def print_data(label, value, mask=False):
    """Helper function to show data"""
    display = "*******" if mask else value
    print(f"\033[1;32m[DATA] {label}: {display}\033[0m")

# Database setup
def init_db():
    print_step("Initializing database...")
    conn = sqlite3.connect('secure_auth.db')
    c = conn.cursor()
    
    print_step("Creating users table if not exists")
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE NOT NULL,
                 password_hash TEXT NOT NULL,
                 salt TEXT NOT NULL,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    print_step("Creating encryption keys table if not exists")
    c.execute('''CREATE TABLE IF NOT EXISTS encryption_keys
                 (id INTEGER PRIMARY KEY,
                 key TEXT NOT NULL)''')
    
    print_step("Checking for existing encryption key")
    c.execute("SELECT key FROM encryption_keys WHERE id = 1")
    if not c.fetchone():
        print_step("Generating new Fernet encryption key")
        key = Fernet.generate_key().decode()
        print_data("Generated key", key)
        c.execute("INSERT INTO encryption_keys VALUES (1, ?)", (key,))
    
    conn.commit()
    conn.close()
    print_step("Database initialization complete")

# Password utilities
def generate_strong_password(length=16):
    print_step("Generating strong password")
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(chars) for _ in range(length))
    print_data("Generated password", password)
    return password

def hash_password(password):
    print_step("Hashing password with bcrypt")
    print_data("Input password", password)
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    print_data("Generated salt", salt.decode())
    print_data("Resulting hash", hashed.decode())
    return hashed.decode(), salt.decode()

def verify_password(input_password, stored_hash):
    print_step("Verifying password")
    print_data("Input password", input_password)
    print_data("Stored hash", stored_hash)
    result = bcrypt.checkpw(input_password.encode(), stored_hash.encode())
    print_data("Verification result", "SUCCESS" if result else "FAILURE")
    return result

# User registration
def register_user():
    print_step("Starting user registration")
    username = input("Enter username: ")
    print_data("Username entered", username)
    
    while True:
        print("\nPassword requirements:")
        print("- At least 8 characters")
        print("- At least one uppercase letter")
        print("- At least one lowercase letter")
        print("- At least one number")
        print("- At least one special character (!@#$%^&*)")
        
        password = getpass("Enter password: ")
            
        if len(password) < 8:
            print("Password too short. Minimum 8 characters required.")
            continue
            
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*" for c in password)
        
        if not (has_upper and has_lower and has_digit and has_special):
            print("Password doesn't meet complexity requirements.")
            continue
            
        break
    
    password_hash, salt = hash_password(password)
    
    print_step("Storing user in database")
    conn = sqlite3.connect('secure_auth.db')
    c = conn.cursor()
    
    try:
        c.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                 (username, password_hash, salt))
        conn.commit()
        print_step("User successfully stored in database")
        print_data("Database record", f"username: {username}, hash: {password_hash[:15]}...")
    except sqlite3.IntegrityError:
        print("Username already exists. Please choose another.")
    finally:
        conn.close()

# User login
def login_user():
    print_step("Starting login process")
    username = input("Username: ")
    password = getpass("Password: ")
    print_data("Login attempt", f"username: {username}", mask=False)
    
    conn = sqlite3.connect('secure_auth.db')
    c = conn.cursor()
    
    print_step("Querying database for user")
    c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    
    if not result:
        print("Login failed: User not found")
        return False
    
    stored_hash = result[0]
    if verify_password(password, stored_hash):
        print("\nLogin successful!")
        return True
    else:
        print("Login failed: Incorrect password")
        return False

# Main menu
def main():
    print_step("Starting authentication system")
    init_db()
    
    while True:
        print("\nSecure Authentication System")
        print("1. Register new user")
        print("2. Login")
        print("3. Exit")
        
        choice = input("Select an option: ")
        
        if choice == "1":
            register_user()
        elif choice == "2":
            login_user()
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()