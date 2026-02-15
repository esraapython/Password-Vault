import mysql.connector
from cryptography.fernet import Fernet
import getpass
import base64

# ----- Connect to the database -----
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="--N0r0ffN1S",  # Replace with your DB password
    database="password_vault"
)

cursor = db.cursor()

# ----- Functions for encryption -----
def derive_key(master_password):
    # Use master password to derive a Fernet key
    key = master_password.ljust(32)[:32].encode()  # simple example; ideally use proper KDF
    return Fernet(base64.urlsafe_b64encode(key))

def encrypt_password(password, fernet):
    return fernet.encrypt(password.encode())

def decrypt_password(enc_password, fernet):
    return fernet.decrypt(enc_password).decode()

# ----- User functions -----
def create_user(username, master_password):
    cursor.execute("SELECT id FROM Users WHERE username=%s", (username,))
    if cursor.fetchone():
        print(f"User {username} already exists!")
        return None
    cursor.execute(
        "INSERT INTO Users (username, master_password_hash) VALUES (%s, %s)",
        (username, master_password)  # store hash if you want; simplified here
    )
    db.commit()
    print(f"User {username} created successfully!")
    return cursor.lastrowid

def get_user_id(username):
    cursor.execute("SELECT id FROM Users WHERE username=%s", (username,))
    result = cursor.fetchone()
    return result[0] if result else None

# ----- Account functions -----
def add_account(user_id, account_name, username, password, description, fernet):
    encrypted_password = encrypt_password(password, fernet)
    cursor.execute(
        "INSERT INTO Accounts (user_id, account_name, username, password, description) VALUES (%s, %s, %s, %s, %s)",
        (user_id, account_name, username, encrypted_password, description)
    )
    db.commit()
    print(f"Account {account_name} added successfully!")

def list_accounts(user_id, fernet):
    cursor.execute("SELECT account_name, username, password, description FROM Accounts WHERE user_id=%s", (user_id,))
    accounts = cursor.fetchall()
    print("\nUser Accounts:")
    for acc in accounts:
        print(f"Account Name: {acc[0]}, Username: {acc[1]}, Password: {decrypt_password(acc[2], fernet)}, Description: {acc[3]}")

def update_account(user_id, fernet):
    account_name = input("Enter the account name to update: ")
    cursor.execute("SELECT id FROM Accounts WHERE user_id=%s AND account_name=%s", (user_id, account_name))
    result = cursor.fetchone()
    if not result:
        print("Account not found!")
        return
    acc_id = result[0]
    new_password = getpass.getpass("Enter new password: ")
    new_description = input("Enter new description: ")
    encrypted_password = encrypt_password(new_password, fernet)
    cursor.execute(
        "UPDATE Accounts SET password=%s, description=%s WHERE id=%s",
        (encrypted_password, new_description, acc_id)
    )
    db.commit()
    print(f"Account {account_name} updated successfully!")

def delete_account(user_id):
    account_name = input("Enter the account name to delete: ")
    cursor.execute("SELECT id FROM Accounts WHERE user_id=%s AND account_name=%s", (user_id, account_name))
    result = cursor.fetchone()
    if not result:
        print("Account not found!")
        return
    confirm = input(f"Are you sure you want to delete the account '{account_name}'? (y/n): ")
    if confirm.lower() != 'y':
        print("Deletion canceled.")
        return
    acc_id = result[0]
    cursor.execute("DELETE FROM Accounts WHERE id=%s", (acc_id,))
    db.commit()
    print(f"Account {account_name} deleted successfully!")

# ----- Main CLI -----
def run_cli():
    print("Password Vault CLI")
    while True:
        choice = input("\nOptions: [1] Create user  [2] Login  [q] Quit\nChoice: ")
        if choice == "1":
            username = input("Enter username: ")
            master_password = getpass.getpass("Enter master password: ")
            create_user(username, master_password)
        elif choice == "2":
            username = input("Enter username: ")
            master_password = getpass.getpass("Enter master password: ")
            user_id = get_user_id(username)
            if not user_id:
                print("Invalid username or password.")
                continue
            fernet = derive_key(master_password)
            print(f"Welcome, {username}!")
            while True:
                action = input("\nActions: [1] Add account  [2] List accounts  [3] Update account  [4] Delete account  [b] Back\nChoice: ")
                if action == "1":
                    acc_name = input("Account name: ")
                    acc_user = input("Username: ")
                    acc_pass = getpass.getpass("Password: ")
                    acc_desc = input("Description: ")
                    add_account(user_id, acc_name, acc_user, acc_pass, acc_desc, fernet)
                elif action == "2":
                    list_accounts(user_id, fernet)
                elif action == "3":
                    update_account(user_id, fernet)
                elif action == "4":
                    delete_account(user_id)
                elif action.lower() == "b":
                    break
                else:
                    print("Invalid choice.")
        elif choice.lower() == "q":
            break
        else:
            print("Invalid option. Try again.")

if __name__ == "__main__":
    run_cli()
    cursor.close()
    db.close()
