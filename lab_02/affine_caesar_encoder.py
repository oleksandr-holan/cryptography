import os


def gcd(a, b):
    """Calculate the greatest common divisor of a and b."""
    while b:
        a, b = b, a % b
    return a


def encrypt_affine_caesar(text, a, b, m=26):
    """
    Encrypt text using the affine Caesar cipher.
    E(x) = (ax + b) mod m

    Parameters:
    text (str): The plaintext to encrypt
    a (int): Coefficient a in the encryption formula
    b (int): Coefficient b in the encryption formula
    m (int): Modulus (default is 26 for English alphabet)

    Returns:
    str: The encrypted text
    """
    if gcd(a, m) != 1:
        raise ValueError(f"'a' and 'm' must be coprime. GCD({a}, {m}) = {gcd(a, m)}")

    result = ""
    for char in text:
        if char.isalpha():
            # Convert to uppercase for simplicity
            is_upper = char.isupper()
            char = char.upper()

            # Convert letter to number (A=0, B=1, ..., Z=25)
            x = ord(char) - ord("A")

            # Apply affine transformation
            y = (a * x + b) % m

            # Convert back to letter
            encrypted_char = chr(y + ord("A"))

            # Preserve original case
            if not is_upper:
                encrypted_char = encrypted_char.lower()

            result += encrypted_char
        else:
            # Keep non-alphabetic characters unchanged
            result += char

    return result


def main():
    print("=== Caesar's Affine Cipher Encryption ===")

    # Get input file path
    input_file = input("Enter the path to the input file: ")
    while not os.path.exists(input_file):
        print("File not found!")
        input_file = input("Enter the path to the input file: ")

    # Get encryption parameters
    try:
        a = int(input("Enter parameter 'a' (must be coprime with 26): "))
        b = int(input("Enter parameter 'b' (0-25): "))

        if gcd(a, 26) != 1:
            print(f"Error: 'a' must be coprime with 26. GCD({a}, 26) = {gcd(a, 26)}")
            return

        if not (0 <= b < 26):
            print("Error: 'b' must be between 0 and 25")
            return
    except ValueError:
        print("Error: Parameters must be integers")
        return

    # Get output file path
    output_file = input("Enter the path for the output file: ")

    # Read input file
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            plaintext = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # Encrypt the text
    ciphertext = encrypt_affine_caesar(plaintext, a, b)

    # Write to output file
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(ciphertext)
        print(f"Encryption successful! Encrypted text saved to {output_file}")
    except Exception as e:
        print(f"Error writing to file: {e}")
        return

    # Display encryption key
    print(f"\nEncryption key: a={a}, b={b}")

    # Display encryption table
    print("\nEncryption Table:")
    print("Plaintext:  ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    encrypted = "".join(
        [
            chr((a * (ord(c) - ord("A")) + b) % 26 + ord("A"))
            for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ]
    )
    print(f"Ciphertext: {encrypted}")


if __name__ == "__main__":
    main()
