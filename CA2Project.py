import logging
import csv
import bcrypt
import re
import requests
import sys
import msvcrt

logging.basicConfig(
    filename='app.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

def store_user(email, password, security_question):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    with open('regno.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([email, hashed_password.decode('utf-8'), security_question])

def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*()_+]", password):
        return False
    return True

def validate_email(email):
    return re.match(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', email)

def get_password_with_asterisks(prompt='Password: '):
    print(prompt, end='', flush=True)
    password = ''
    while True:
        char = msvcrt.getch()
        if char == b'\r':  
            print('')
            break
        elif char == b'\x08':  
            if len(password) > 0:
                password = password[:-1]
                print('\b \b', end='', flush=True)
        else:
            password += char.decode('utf-8')
            print('*', end='', flush=True)
    return password

def register():
    email = input("Enter your email: ")
    if not validate_email(email):
        print("Invalid email format.")
        return
    password = get_password_with_asterisks()
    if not validate_password(password):
        print("Password does not meet criteria.")
        return
    print("Security Question\n")
    security_question = input("What is your favorite color : ")
    try:
        with open('regno.csv', mode='r') as file:
            reader = csv.reader(file)
            for row in reader:
                if row and row[0] == email:
                    print("Email already registered.")
                    return
    except FileNotFoundError:
        print("User data file not found. It will be created upon registration.")
    store_user(email, password, security_question)
    print("Registration successful!")
    logging.info(f"User registered: {email}")

def login():
    email = input("Enter email: ")
    if not validate_email(email):
        print("Invalid email format.")
        return False
    password = get_password_with_asterisks()
    with open('regno.csv', mode='r') as file:
        reader = csv.reader(file)
        for row in reader:
            if row and row[0] == email:
                stored_hashed_password = row[1]
                if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
                    print("Login successful!")
                    logging.info(f"User logged in: {email}")
                    return True
                else:
                    print("Incorrect password.")
                    logging.warning(f"Incorrect password attempt for email: {email}")
                    return False
    print("Email not found.")
    logging.warning(f"Email not found: {email}")
    return False

def forgot_password():
    email = input("Enter registered email: ")
    with open('regno.csv', mode='r') as file:
        reader = csv.reader(file)
        rows = list(reader)
    for row in rows:
        if row and row[0] == email:
            security_question = row[2]
            answer = input(f"{security_question}: ")
            if answer == "YourAnswer":
                new_password = get_password_with_asterisks("Enter new password: ")
                if validate_password(new_password):
                    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                    row[1] = hashed_password.decode('utf-8')
                    with open('regno.csv', mode='w', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerows(rows)
                    print("Password reset successfully!")
                    logging.info(f"Password reset for email: {email}")
                else:
                    print("Password does not meet criteria.")
            else:
                print("Incorrect answer.")
            return
    print("Email not found.")
    logging.warning(f"Password reset attempt failed: Email not found: {email}")

def login_attempts():
    attempts = 0
    max_attempts = 5
    while attempts < max_attempts:
        success = login()
        if success:
            return True
        else:
            attempts += 1
            print(f"Login failed. {max_attempts - attempts} attempts remaining.")
            if attempts == 1:
                reset_choice = input("Would you like to reset your password? (yes/no): ").strip().lower()
                if reset_choice == 'yes':
                    forgot_password()
                    return False
        if attempts == max_attempts:
            print("Too many failed attempts.")
            logging.warning("Too many failed login attempts.")
            return False
    return False

def get_geolocation(ip_address=None):
    api_key = '034d08c122ff8c24c741c4258ba7ca10'
    if not ip_address:
        ip_address = requests.get('https://api.ipify.org').text
    url = f"http://api.ipstack.com/{ip_address}?access_key={api_key}"
    response = requests.get(url).json()
    if 'error' in response:
        print(f"Error: {response['error']['info']}")
        logging.error(f"API error: {response['error']['info']}")
        return
    print(f"Country: {response.get('country_name', 'N/A')}")
    print(f"City: {response.get('city', 'N/A')}")
    print(f"Region: {response.get('region_name', 'N/A')}")
    print(f"Latitude: {response.get('latitude', 'N/A')}")
    print(f"Longitude: {response.get('longitude', 'N/A')}")
    if 'time_zone' in response and 'id' in response['time_zone']:
        print(f"Timezone: {response['time_zone']['id']}")
    else:
        print("Timezone: N/A")
    if 'connection' in response and 'isp' in response['connection']:
        print(f"ISP: {response['connection']['isp']}")
    else:
        print("ISP: N/A")
    logging.info(f"Geolocation details fetched for IP: {ip_address}")

def main():
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice: ")
        if choice == '1':
            register()
        elif choice == '2':
            if login_attempts():
                ip = input("Enter IP address (or press Enter to use your own IP): ")
                get_geolocation(ip if ip else None)
        elif choice == '3':
            print("Exiting application.")
            logging.info("Application exited.")
            break
        else:
            print("Invalid choice.")
            logging.warning(f"Invalid menu choice: {choice}")

if __name__ == "__main__":
    main()
 
