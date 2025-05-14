UKRAINIAN_LOWER = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"
UKRAINIAN_UPPER = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
ALPHABET_SIZE = len(UKRAINIAN_LOWER)  # 33 літери


def process_char(char, shift, alphabet):
    """
    Обробляє одну літеру: шифрує або розшифровує.
    Якщо символ не є літерою з наданого алфавіту, він повертається без змін.
    """
    if char in alphabet:
        char_index = alphabet.find(char)
        shifted_index = (char_index + shift) % ALPHABET_SIZE
        # Для від'ємних зсувів (розшифрування) Python % працює коректно:
        # наприклад, (-1 + 33) % 33 == 32 % 33 == 32
        return alphabet[shifted_index]
    return char


def caesar_cipher(text, shift, encrypt_mode=True):
    """
    Шифрує або розшифровує текст шифром Цезаря.
    encrypt_mode=True для шифрування, False для розшифрування.
    """
    processed_text = []
    # Для розшифрування ми використовуємо той самий зсув, але в зворотньому напрямку
    # Це еквівалентно додаванню (ALPHABET_SIZE - shift) % ALPHABET_SIZE
    # Або просто передаємо негативний зсув, якщо process_char це обробляє
    # Для простоти, ми інвертуємо зсув для розшифрування тут
    if not encrypt_mode:
        shift = -shift

    for char in text:
        if char in UKRAINIAN_LOWER:
            processed_text.append(process_char(char, shift, UKRAINIAN_LOWER))
        elif char in UKRAINIAN_UPPER:
            processed_text.append(process_char(char, shift, UKRAINIAN_UPPER))
        else:
            processed_text.append(char)  # Залишаємо символи, що не є літерами
    return "".join(processed_text)


# --- Програма шифрування ---
def encrypt_program():
    print("--- ПРОГРАМА ШИФРУВАННЯ ---")
    try:
        input_filename = input("Введіть ім'я файлу для читання (наприклад, text.txt): ")
        with open(input_filename, "r", encoding="utf-8") as f_in:
            original_text = f_in.read()
    except FileNotFoundError:
        print(f"Помилка: Файл '{input_filename}' не знайдено.")
        return
    except Exception as e:
        print(f"Сталася помилка при читанні файлу: {e}")
        return

    while True:
        try:
            shift = int(input("Введіть значення зсуву (ціле число): "))
            break
        except ValueError:
            print("Будь ласка, введіть дійсне ціле число для зсуву.")

    encrypted_text = caesar_cipher(original_text, shift, encrypt_mode=True)

    try:
        output_filename = input(
            "Введіть ім'я файлу для збереження зашифрованого тексту (наприклад, encrypted.txt): "
        )
        with open(output_filename, "w", encoding="utf-8") as f_out:
            f_out.write(encrypted_text)
        print(f"Текст успішно зашифровано та збережено у файл '{output_filename}'.")
    except Exception as e:
        print(f"Сталася помилка при записі у файл: {e}")


# --- Програма розшифрування ---
def decrypt_program():
    print("\n--- ПРОГРАМА РОЗШИФРУВАННЯ ---")
    try:
        input_filename = input(
            "Введіть ім'я файлу з зашифрованим текстом (наприклад, encrypted.txt): "
        )
        with open(input_filename, "r", encoding="utf-8") as f_in:
            encrypted_text = f_in.read()
    except FileNotFoundError:
        print(f"Помилка: Файл '{input_filename}' не знайдено.")
        return
    except Exception as e:
        print(f"Сталася помилка при читанні файлу: {e}")
        return

    while True:
        try:
            # Важливо: для розшифрування потрібно знати той самий зсув,
            # що використовувався при шифруванні.
            shift = int(
                input("Введіть значення зсуву, що використовувалося для шифрування: ")
            )
            break
        except ValueError:
            print("Будь ласка, введіть дійсне ціле число для зсуву.")

    decrypted_text = caesar_cipher(encrypted_text, shift, encrypt_mode=False)

    print("\nРозшифрований текст:")
    print(decrypted_text)
    print("-" * 20)


# --- Головне меню для вибору дії ---
if __name__ == "__main__":
    while True:
        choice = input(
            "Виберіть дію:\n1. Шифрувати текст\n2. Розшифрувати текст\n3. Вийти\nВаш вибір: "
        )
        if choice == "1":
            encrypt_program()
        elif choice == "2":
            decrypt_program()
        elif choice == "3":
            print("Вихід з програми.")
            break
        else:
            print("Невірний вибір. Спробуйте ще раз.")
        print("\n")
