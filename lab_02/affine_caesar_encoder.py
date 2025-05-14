import os

# Визначення українського алфавіту та його параметрів
UKRAINIAN_ALPHABET = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
M_UKRAINIAN = len(UKRAINIAN_ALPHABET)  # Модуль для українського алфавіту (33)
BASE_CHAR_UKR_UPPER = UKRAINIAN_ALPHABET[0]  # 'А'
BASE_CHAR_UKR_LOWER = UKRAINIAN_ALPHABET[0].lower()  # 'а'


def gcd(a, b):
    """Обчислити найбільший спільний дільник a та b."""
    while b:
        a, b = b, a % b
    return a


def modInverse(a, m):
    """Обчислити модульне мультиплікативне обернене число a за модулем m."""
    if gcd(a, m) != 1:
        return None  # Обернене не існує, якщо a та m не є взаємно простими
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None  # Не повинно досягатися, якщо gcd(a,m)==1 та m > 1


def encrypt_affine_caesar(text, a, b, m=M_UKRAINIAN, alphabet_chars=UKRAINIAN_ALPHABET):
    """
    Зашифрувати текст за допомогою афінного шифру Цезаря.
    E(x) = (ax + b) mod m

    Параметри:
    text (str): Відкритий текст для шифрування
    a (int): Коефіцієнт a у формулі шифрування
    b (int): Коефіцієнт b у формулі шифрування
    m (int): Модуль (за замовчуванням M_UKRAINIAN для українського алфавіту)
    alphabet_chars (str): Рядок, що містить символи алфавіту

    Повертає:
    str: Зашифрований текст
    """
    if gcd(a, m) != 1:
        raise ValueError(
            f"'a' ({a}) та 'm' ({m}) повинні бути взаємно простими. НСД({a}, {m}) = {gcd(a, m)}"
        )

    result = ""
    alphabet_map_upper = {char: i for i, char in enumerate(alphabet_chars)}
    alphabet_map_lower = {char.lower(): i for i, char in enumerate(alphabet_chars)}

    base_char_upper_ord = ord(alphabet_chars[0])
    base_char_lower_ord = ord(alphabet_chars[0].lower())

    for char_original in text:
        char_to_process = char_original
        is_upper = char_to_process.isupper()

        if (
            char_to_process.upper() in alphabet_map_upper
        ):  # Перевіряємо, чи є літера в нашому алфавіті
            if is_upper:
                x = alphabet_map_upper[char_to_process]
            else:
                x = alphabet_map_lower[char_to_process]

            # Застосувати афінне перетворення
            y = (a * x + b) % m

            # Перетворити назад на літеру
            encrypted_char = alphabet_chars[y]

            # Зберегти оригінальний регістр
            if not is_upper:
                encrypted_char = encrypted_char.lower()

            result += encrypted_char
        else:
            # Залишити неалфавітні символи без змін
            result += char_original
    return result


def decrypt_affine_caesar(
    ciphertext, a, b, m=M_UKRAINIAN, alphabet_chars=UKRAINIAN_ALPHABET
):
    """
    Розшифрувати текст за допомогою афінного шифру Цезаря.
    D(y) = a_inv * (y - b) mod m

    Параметри:
    ciphertext (str): Шифротекст для розшифрування
    a (int): Коефіцієнт a в оригінальній формулі шифрування
    b (int): Коефіцієнт b в оригінальній формулі шифрування
    m (int): Модуль (за замовчуванням M_UKRAINIAN для українського алфавіту)
    alphabet_chars (str): Рядок, що містить символи алфавіту

    Повертає:
    str: Розшифрований текст
    """
    if gcd(a, m) != 1:
        raise ValueError(
            f"'a' ({a}) та 'm' ({m}) повинні бути взаємно простими для розшифрування. НСД({a}, {m}) = {gcd(a, m)}"
        )

    a_inv = modInverse(a, m)
    if a_inv is None:
        # Цей випадок ідеально мав би бути перехоплений перевіркою gcd вище
        raise ValueError(
            f"Модульне обернене для {a} за модулем {m} не існує. Розшифрування неможливе."
        )

    result = ""
    alphabet_map_upper = {char: i for i, char in enumerate(alphabet_chars)}
    alphabet_map_lower = {char.lower(): i for i, char in enumerate(alphabet_chars)}

    base_char_upper_ord = ord(alphabet_chars[0])
    base_char_lower_ord = ord(alphabet_chars[0].lower())

    for char_original in ciphertext:
        char_to_process = char_original
        is_upper = char_to_process.isupper()

        if (
            char_to_process.upper() in alphabet_map_upper
        ):  # Перевіряємо, чи є літера в нашому алфавіті
            if is_upper:
                y = alphabet_map_upper[char_to_process]
            else:
                y = alphabet_map_lower[char_to_process]

            # Застосувати афінне розшифрування: x = a_inv * (y - b) mod m
            # (y - b + m) гарантує, що аргумент для % буде невід'ємним
            x = (a_inv * (y - b + m)) % m

            # Перетворити назад на літеру
            decrypted_char = alphabet_chars[x]

            # Зберегти оригінальний регістр
            if not is_upper:
                decrypted_char = decrypted_char.lower()

            result += decrypted_char
        else:
            # Залишити неалфавітні символи без змін
            result += char_original
    return result


def main():
    print("=== Афінний шифр Цезаря ===")

    while True:
        mode = input(
            "Ви хочете (ш)ифрувати чи (р)озшифрувати? Введіть 'ш' або 'р': "
        ).lower()
        if mode in ["ш", "шифрувати", "р", "розшифрувати"]:
            break
        print(
            "Неправильний вибір. Будь ласка, введіть 'ш' (шифрувати) або 'р' (розшифрувати)."
        )

    # Отримати шлях до вхідного файлу
    file_type_for_input = "відкритого тексту" if mode.startswith("ш") else "шифротексту"
    input_file_prompt = f"Введіть шлях до вхідного файлу {file_type_for_input}: "

    input_file = input(input_file_prompt)
    while not os.path.exists(input_file):
        print("Файл не знайдено!")
        input_file = input(input_file_prompt)

    # Отримати параметри шифру
    m = M_UKRAINIAN  # Модуль для українського алфавіту
    print(f"Використовується український алфавіт (модуль m = {m}).")
    try:
        a = int(input(f"Введіть параметр 'a' (має бути взаємно простим з {m}): "))
        b = int(input(f"Введіть параметр 'b' (0-{m - 1}): "))

        if gcd(a, m) != 1:
            print(
                f"Помилка: 'a' ({a}) має бути взаємно простим з {m}. НСД({a}, {m}) = {gcd(a, m)}"
            )
            return

        if not (0 <= b < m):
            print(f"Помилка: 'b' має бути в межах від 0 до {m - 1}")
            return
    except ValueError:
        print("Помилка: Параметри 'a' та 'b' повинні бути цілими числами.")
        return

    # Отримати шлях до вихідного файлу
    file_type_for_output = (
        "шифротексту" if mode.startswith("ш") else "відкритого тексту"
    )
    output_file_prompt = f"Введіть шлях для вихідного файлу {file_type_for_output}: "
    output_file = input(output_file_prompt)

    # Прочитати вхідний файл
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            text_data = f.read()
    except Exception as e:
        print(f"Помилка читання файлу '{input_file}': {e}")
        return

    processed_text = ""
    operation_status = ""

    if mode.startswith("ш"):  # Шифрування
        try:
            processed_text = encrypt_affine_caesar(
                text_data, a, b, m, UKRAINIAN_ALPHABET
            )
            operation_status = (
                f"Шифрування успішне! Зашифрований текст збережено у {output_file}"
            )
        except ValueError as e:
            print(f"Помилка шифрування: {e}")
            return
    else:  # Розшифрування (mode.startswith('р'))
        try:
            processed_text = decrypt_affine_caesar(
                text_data, a, b, m, UKRAINIAN_ALPHABET
            )
            operation_status = (
                f"Розшифрування успішне! Розшифрований текст збережено у {output_file}"
            )
        except ValueError as e:
            print(f"Помилка розшифрування: {e}")
            return

    # Записати у вихідний файл
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(processed_text)
        print(operation_status)
    except Exception as e:
        print(f"Помилка запису у файл '{output_file}': {e}")
        return

    # Відобразити ключ
    print(f"\nВикористаний ключ: a={a}, b={b}, m={m}")

    # Відобразити таблицю
    if mode.startswith("ш"):
        print("\nТаблиця шифрування:")
        print(f"Відкритий текст:  {UKRAINIAN_ALPHABET}")
        encrypted_alphabet_display = encrypt_affine_caesar(
            UKRAINIAN_ALPHABET, a, b, m, UKRAINIAN_ALPHABET
        )
        print(f"Шифротекст:       {encrypted_alphabet_display}")
    else:  # Розшифрування
        print("\nТаблиця розшифрування:")
        print(f"Шифротекст:       {UKRAINIAN_ALPHABET}")
        # Щоб показати розшифрування, застосовуємо функцію розшифрування до стандартного алфавіту (ніби це шифротекст)
        decrypted_alphabet_display = decrypt_affine_caesar(
            UKRAINIAN_ALPHABET, a, b, m, UKRAINIAN_ALPHABET
        )
        print(f"Відкритий текст:  {decrypted_alphabet_display}")


if __name__ == "__main__":
    main()
