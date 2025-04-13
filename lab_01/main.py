import os
from collections import Counter

import matplotlib.pyplot as plt


def read_encrypted_file(file_path):
    """Читає зашифрований файл"""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return file.read()
    except FileNotFoundError:
        print(f"Помилка: Файл {file_path} не знайдено.")
        return None
    except Exception as e:
        print(f"Помилка при читанні файлу: {e}")
        return None


def calculate_frequencies(text):
    """Розраховує відносну частоту кожного символу в тексті"""
    # Видаляємо пробіли та переводимо текст у нижній регістр
    text = "".join(c for c in text.lower() if c.isalpha())

    # Підраховуємо кількість кожного символу
    char_count = Counter(text)

    # Розраховуємо відносну частоту
    total_chars = len(text)
    frequencies = {char: count / total_chars for char, count in char_count.items()}

    return frequencies, total_chars


def display_frequencies(frequencies, total_chars):
    """Відображає частоти символів у консолі та на графіку"""
    print(f"\nАналіз тексту (загальна кількість символів: {total_chars}):")
    print("Символ | Кількість | Відносна частота")
    print("-" * 40)

    # Сортуємо за частотою (від найбільшої до найменшої)
    sorted_freq = sorted(frequencies.items(), key=lambda x: x[1], reverse=True)

    for char, freq in sorted_freq:
        count = int(freq * total_chars)
        print(f"   {char}   |    {count:5d}   |    {freq:.6f}")

    # Створюємо графік
    chars = [item[0] for item in sorted_freq]
    freqs = [item[1] for item in sorted_freq]

    plt.figure(figsize=(12, 6))
    plt.bar(chars, freqs)
    plt.title("Частотний аналіз символів")
    plt.xlabel("Символи")
    plt.ylabel("Відносна частота")
    plt.show()

    return sorted_freq


def suggest_caesar_shifts(frequencies):
    """Пропонує можливі зсуви для шифру Цезаря"""
    # Найчастіші літери в українській мові
    ukr_common_letters = ["о", "а", "н", "і", "и", "в", "е", "р", "т", "с"]

    # Беремо найчастіші літери з зашифрованого тексту
    most_common = [char for char, _ in frequencies[:5]]

    print("\nМожливі ключі шифру Цезаря:")
    print("Припускаючи, що найчастіша літера це:")

    for common_letter in ukr_common_letters[:3]:  # Перевіряємо для 3 найчастіших літер
        for encrypted_letter in most_common:
            # Український алфавіт
            alphabet = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"

            # Знаходимо позиції літер в алфавіті
            pos_common = alphabet.find(common_letter)
            pos_encrypted = alphabet.find(encrypted_letter)

            if pos_common != -1 and pos_encrypted != -1:
                # Розраховуємо зсув
                shift = (pos_encrypted - pos_common) % len(alphabet)
                print(f"'{common_letter}' -> '{encrypted_letter}': зсув = {shift}")


def decrypt_with_shift(text, shift):
    """Розшифровує текст із заданим зсувом"""
    alphabet = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"
    result = ""

    for char in text:
        if char.lower() in alphabet:
            is_upper = char.isupper()
            char_lower = char.lower()
            idx = alphabet.find(char_lower)

            if idx != -1:
                new_idx = (idx - shift) % len(alphabet)
                new_char = alphabet[new_idx]

                if is_upper:
                    new_char = new_char.upper()

                result += new_char
            else:
                result += char
        else:
            result += char

    return result


def try_decrypt(text):
    """Дозволяє користувачу спробувати різні зсуви для розшифрування"""
    while True:
        try:
            shift = int(
                input("\nВведіть зсув для спроби розшифрування (або -1 для виходу): ")
            )

            if shift == -1:
                break

            decrypted = decrypt_with_shift(text, shift)
            print("\nРозшифрований текст з зсувом", shift, ":")
            print("-" * 50)
            print(decrypted[:500])  # Показуємо перші 500 символів
            print("-" * 50)

            choice = input("Це правильне розшифрування? (так/ні): ").lower()
            if choice == "так":
                print("\nУспішно розшифровано з ключем (зсувом):", shift)
                return shift

        except ValueError:
            print("Будь ласка, введіть ціле число.")


def main():
    print("Програма криптоаналізу шифру Цезаря")
    file_path = input("Введіть шлях до зашифрованого файлу: ")

    encrypted_text = read_encrypted_file(file_path)
    if not encrypted_text:
        return

    print("\nЗашифрований текст (перші 100 символів):")
    print(encrypted_text[:100])

    frequencies, total_chars = calculate_frequencies(encrypted_text)
    sorted_freq = display_frequencies(frequencies, total_chars)

    suggest_caesar_shifts(sorted_freq)

    found_key = try_decrypt(encrypted_text)

    if found_key is not None:
        # Зберігаємо розшифрований текст
        decrypted_text = decrypt_with_shift(encrypted_text, found_key)
        output_path = os.path.splitext(file_path)[0] + "_decrypted.txt"

        try:
            with open(output_path, "w", encoding="utf-8") as file:
                file.write(decrypted_text)
            print(f"Розшифрований текст збережено у файлі: {output_path}")
        except Exception as e:
            print(f"Помилка при збереженні розшифрованого тексту: {e}")


if __name__ == "__main__":
    main()
