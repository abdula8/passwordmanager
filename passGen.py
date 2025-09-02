import random
import string

def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

# Example usage
# while(1):
#     password_length = input("Enter Password Length or q to exit: ")
#     try:
#         if password_length.lower() == "q":
#             break
#         password_length = int(password_length)
#         print("Generated password:", generate_password(password_length))
            
#     except:
#         print("Enter an integer number as a password length like 15 to generate password with length of 15 characters\n or q, Q to exit...")
