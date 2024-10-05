import csv
import re
import bcrypt
import requests
from getpass import getpass
import logging

CSV_FILE = 'users.csv'
LOG_FILE = 'activity.log'
MAX_LOGIN_ATTEMPTS = 5
API_BASE_URL = 'https://www.cheapshark.com/api/1.0'

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

def load_users():
    users = {}
    try:
        with open(CSV_FILE, 'r', newline='') as file:
            reader = csv.DictReader(file)
            for row in reader:
                users[row['email']] = {
                    'password': row['password'],
                    'security_question': row['security_question'],
                    'security_answer': row['security_answer']
                }
    except FileNotFoundError:
        pass
    return users

def save_users(users):
    with open(CSV_FILE, 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['email', 'password', 'security_question', 'security_answer'])
        writer.writeheader()
        for email, data in users.items():
            writer.writerow({
                'email': email,
                'password': data['password'],
                'security_question': data['security_question'],
                'security_answer': data['security_answer']
            })

def register_user(users):
    print("\n--- User Registration ---")
    email = input("Enter your email: ")
    if email in users:
        print("Email already registered.")
        return

    if not is_valid_email(email):
        print("Invalid email format.")
        return

    password = getpass("Enter your password: ")
    if not is_valid_password(password):
        print("Invalid password. It must be at least 8 characters long and contain uppercase, lowercase, number, and special character.")
        return

    security_question = input("Enter a security question: ")
    security_answer = input("Enter the answer to your security question: ")

    users[email] = {
        'password': hash_password(password),
        'security_question': security_question,
        'security_answer': security_answer
    }
    save_users(users)
    logging.info(f"New user registered: {email}")
    print("User registered successfully!")

def login(users):
    attempts = 0
    while attempts < MAX_LOGIN_ATTEMPTS:
        print("\n--- User Login ---")
        email = input("Enter your email: ")
        password = getpass("Enter your password: ")

        if email in users and verify_password(password, users[email]['password']):
            print("Login successful!")
            logging.info(f"User logged in: {email}")
            return email
        else:
            attempts += 1
            print(f"Invalid email or password. {MAX_LOGIN_ATTEMPTS - attempts} attempts remaining.")
            logging.warning(f"Failed login attempt for user: {email}")

    print("Maximum login attempts exceeded. Please try again later.")
    logging.warning(f"User exceeded maximum login attempts: {email}")
    return None

def forgot_password(users):
    print("\n--- Password Recovery ---")
    email = input("Enter your email: ")
    if email not in users:
        print("Email not found.")
        return

    security_question = users[email]['security_question']
    answer = input(f"Security Question: {security_question}\nYour answer: ")

    if answer.lower() == users[email]['security_answer'].lower():
        new_password = getpass("Enter new password: ")
        if is_valid_password(new_password):
            users[email]['password'] = hash_password(new_password)
            save_users(users)
            logging.info(f"Password reset for user: {email}")
            print("Password reset successfully!")
        else:
            print("Invalid password. It must be at least 8 characters long and contain uppercase, lowercase, number, and special character.")
    else:
        print("Incorrect answer to security question.")
        logging.warning(f"Failed password recovery attempt for user: {email}")

def get_game_deals(game_title):
    url = f"{API_BASE_URL}/deals?title={game_title}&sortBy=Price"
    response = requests.get(url)
    if response.status_code == 200:
        logging.info(f"Successfully retrieved deals for game: {game_title}")
        return response.json()
    else:
        logging.error(f"Error fetching game deals for {game_title}: {response.status_code}")
        print(f"Error fetching data: {response.status_code}")
        return None

def display_game_deals(deals):
    if not deals:
        print("No deals found for this game.")
        return

    print("\n--- Game Deals ---")
    for deal in deals[:5]:
        print(f"Game: {deal['title']}")
        print(f"Store: {deal['storeID']}")
        print(f"Normal Price: ${deal['normalPrice']}")
        print(f"Sale Price: ${deal['salePrice']}")
        print(f"Savings: {deal['savings']}%")
        print(f"Deal Rating: {deal['dealRating']}")
        print(f"Deal Link: https://www.cheapshark.com/redirect?dealID={deal['dealID']}")
        print("---")

def main():
    users = load_users()
    logged_in_user = None

    while True:
        if not logged_in_user:
            print("\n1. Login")
            print("2. Register")
            print("3. Forgot Password")
            print("4. Quit")
            choice = input("Enter your choice: ")

            if choice == '1':
                logged_in_user = login(users)
            elif choice == '2':
                register_user(users)
            elif choice == '3':
                forgot_password(users)
            elif choice == '4':
                print("Goodbye!")
                logging.info("Application closed.")
                break
            else:
                print("Invalid choice. Please try again.")
        else:
            print("\n--- Game Price Search ---")
            game_title = input("Enter a game title (or 'logout' to exit): ")
            if game_title.lower() == 'logout':
                logging.info(f"User logged out: {logged_in_user}")
                logged_in_user = None
                print("Logged out successfully.")
            else:
                deals = get_game_deals(game_title)
                display_game_deals(deals)

if __name__ == "__main__":
    main()
