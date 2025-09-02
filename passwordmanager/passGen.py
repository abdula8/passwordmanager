import random
import string

def generate_password(length=12, use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True):
    """Generate a random password based on specified criteria."""
    if length < 1:
        raise ValueError("Password length must be at least 1.")

    character_pool = ""
    if use_uppercase:
        character_pool += string.ascii_uppercase
    if use_lowercase:
        character_pool += string.ascii_lowercase
    if use_digits:
        character_pool += string.digits
    if use_symbols:
        character_pool += string.punctuation

    if not character_pool:
        raise ValueError("At least one character type must be selected.")

    password = ''.join(random.choice(character_pool) for _ in range(length))
    return password

def main():
    """Main function to demonstrate password generation."""
    print("Generated Passwords:")
    for _ in range(5):
        print(generate_password(length=16))

if __name__ == "__main__":
    main()