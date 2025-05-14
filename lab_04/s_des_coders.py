import sys

# --- Константи та таблиці перестановок/замін (0-індексовані) ---

# Для генерації ключів
# P10: 3 5 2 7 4 10 1 9 8 6 -> 2 4 1 6 3 9 0 8 7 5
P10_TABLE = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]
# P8:  6 3 7 4 8 5 10 9 -> 5 2 6 3 7 4 9 8
P8_TABLE = [5, 2, 6, 3, 7, 4, 9, 8]

# Для шифрування/розшифрування
# IP:  2 6 3 1 4 8 5 7 -> 1 5 2 0 3 7 4 6
IP_TABLE = [1, 5, 2, 0, 3, 7, 4, 6]
# IP-1: 4 1 3 5 7 2 8 6 -> 3 0 2 4 6 1 7 5
IP_INV_TABLE = [3, 0, 2, 4, 6, 1, 7, 5]
# Розширення/Перестановка: 4 1 2 3 2 3 4 1 -> 3 0 1 2 1 2 3 0
EP_TABLE = [3, 0, 1, 2, 1, 2, 3, 0]
# P4: 2 4 3 1 -> 1 3 2 0
P4_TABLE = [1, 3, 2, 0]

# S-блоки
S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2],
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3],
]


def permute(data_bits, permutation_table):
    """Виконує перестановку бітів згідно з таблицею."""
    return "".join(data_bits[i] for i in permutation_table)


def left_shift(data_bits, shifts):
    """Виконує циклічний зсув ліворуч."""
    return data_bits[shifts:] + data_bits[:shifts]


def xor(bits1, bits2):
    """Виконує побітове XOR для двох бітових рядків."""
    return "".join(str(int(b1) ^ int(b2)) for b1, b2 in zip(bits1, bits2))


def split_half(data_bits):
    """Розділяє бітовий рядок навпіл."""
    mid = len(data_bits) // 2
    return data_bits[:mid], data_bits[mid:]


def get_sbox_value(four_bits, sbox):
    """Отримує значення з S-блоку."""
    row = int(four_bits[0] + four_bits[3], 2)  # Перший та четвертий біти -> номер рядка
    col = int(four_bits[1] + four_bits[2], 2)  # Другий та третій біти -> номер стовпця
    value = sbox[row][col]
    return format(value, "02b")  # Повертає 2-бітне двійкове представлення


# --- Генерація ключів ---
def generate_keys(key_10bit):
    """Генерує два 8-бітних підключі K1 та K2 з 10-бітного ключа."""
    if len(key_10bit) != 10 or not all(c in "01" for c in key_10bit):
        raise ValueError("Ключ повинен бути 10-бітним двійковим рядком")

    # 1. P10
    p10_key = permute(key_10bit, P10_TABLE)

    # 2. Розділення на дві половини
    left, right = split_half(p10_key)

    # 3. LS-1 для обох половин
    ls1_left = left_shift(left, 1)
    ls1_right = left_shift(right, 1)

    # 4. P8 для отримання K1
    k1 = permute(ls1_left + ls1_right, P8_TABLE)

    # 5. LS-2 для кожної з *попередніх* (зсунутих на 1) половин
    ls2_left = left_shift(ls1_left, 2)
    ls2_right = left_shift(ls1_right, 2)

    # 6. P8 для отримання K2
    k2 = permute(ls2_left + ls2_right, P8_TABLE)

    return k1, k2


# --- Функція f (внутрішня частина FK) ---
def function_f(right_4bit, subkey_8bit, s0, s1):
    """Виконує операції всередині циклової функції FK."""
    # Розширення/Перестановка (E/P)
    expanded_bits = permute(right_4bit, EP_TABLE)

    # XOR з підключем
    xored_bits = xor(expanded_bits, subkey_8bit)

    # Розділення для S-блоків
    left_xor, right_xor = split_half(xored_bits)

    # Заміна в S-блоках
    s0_output = get_sbox_value(left_xor, s0)
    s1_output = get_sbox_value(right_xor, s1)

    # Об'єднання та перестановка P4
    p4_output = permute(s0_output + s1_output, P4_TABLE)

    return p4_output


# --- Циклова функція FK ---
def function_fk(data_8bit, subkey_8bit, s0, s1):
    """Виконує повну циклову функцію FK."""
    left, right = split_half(data_8bit)
    f_result = function_f(right, subkey_8bit, s0, s1)
    new_left = xor(left, f_result)
    # Результат FK - це (L XOR f(R, K), R)
    return new_left + right


# --- Перестановка SW ---
def swap(data_8bit):
    """Міняє місцями ліву та праву 4-бітні половини."""
    left, right = split_half(data_8bit)
    return right + left


# --- Шифрування одного 8-бітного блоку ---
def encrypt_block(plaintext_8bit, key_10bit, s0, s1):
    """Шифрує один 8-бітний блок за допомогою S-DES."""
    if len(plaintext_8bit) != 8 or not all(c in "01" for c in plaintext_8bit):
        raise ValueError("Відкритий текст повинен бути 8-бітним двійковим рядком")

    k1, k2 = generate_keys(key_10bit)

    # 1. Початкова перестановка IP
    ip_result = permute(plaintext_8bit, IP_TABLE)

    # 2. Циклова функція FK з K1
    fk1_result = function_fk(ip_result, k1, s0, s1)

    # 3. Перестановка SW
    swapped = swap(fk1_result)

    # 4. Циклова функція FK з K2
    fk2_result = function_fk(swapped, k2, s0, s1)

    # 5. Кінцева перестановка IP-1
    ciphertext_8bit = permute(fk2_result, IP_INV_TABLE)

    return ciphertext_8bit


# --- Розшифрування одного 8-бітного блоку ---
def decrypt_block(ciphertext_8bit, key_10bit, s0, s1):
    """Розшифровує один 8-бітний блок за допомогою S-DES."""
    if len(ciphertext_8bit) != 8 or not all(c in "01" for c in ciphertext_8bit):
        raise ValueError("Шифротекст повинен бути 8-бітним двійковим рядком")

    k1, k2 = generate_keys(key_10bit)  # Ключі генеруються так само

    # 1. Початкова перестановка IP
    ip_result = permute(ciphertext_8bit, IP_TABLE)

    # 2. Циклова функція FK з K2 (зворотний порядок ключів!)
    fk1_result = function_fk(ip_result, k2, s0, s1)

    # 3. Перестановка SW
    swapped = swap(fk1_result)

    # 4. Циклова функція FK з K1 (зворотний порядок ключів!)
    fk2_result = function_fk(swapped, k1, s0, s1)

    # 5. Кінцева перестановка IP-1
    plaintext_8bit = permute(fk2_result, IP_INV_TABLE)

    return plaintext_8bit


# --- Функції для роботи з текстом ---


def text_to_binary(text):
    """Перетворює текстовий рядок у рядок 8-бітних двійкових блоків."""
    binary_string = ""
    for char in text:
        # Використовуємо UTF-8 і беремо молодші 8 біт, якщо символ > 255
        # Для простоти можна обмежитись ASCII або обробляти помилки
        try:
            char_code = ord(char)
            if char_code > 255:
                print(
                    f"Попередження: Символ '{char}' (код {char_code}) буде усічено до 8 біт.",
                    file=sys.stderr,
                )
            binary_string += format(char_code & 0xFF, "08b")  # Беремо молодші 8 біт
        except Exception as e:
            print(f"Помилка кодування символу '{char}': {e}", file=sys.stderr)
            binary_string += "00000000"  # Додаємо нульовий блок у разі помилки
    return binary_string


def binary_to_text(binary_string):
    """Перетворює рядок 8-бітних двійкових блоків у текст."""
    text = ""
    if len(binary_string) % 8 != 0:
        print(
            "Попередження: Довжина двійкового рядка не кратна 8. Можлива втрата даних.",
            file=sys.stderr,
        )

    for i in range(0, len(binary_string), 8):
        byte = binary_string[i : i + 8]
        if len(byte) < 8:  # Якщо залишився неповний байт
            print(
                f"Попередження: Пропускається неповний байт в кінці: {byte}",
                file=sys.stderr,
            )
            continue
        try:
            text += chr(int(byte, 2))
        except ValueError:
            print(
                f"Попередження: Неможливо перетворити байт '{byte}' на символ. Замінено на '?'.",
                file=sys.stderr,
            )
            text += "?"  # Або інший символ за замовчуванням
        except Exception as e:
            print(f"Помилка декодування байта '{byte}': {e}", file=sys.stderr)
            text += "?"
    return text


def process_text(text, key_10bit, mode):
    """Шифрує або розшифровує текст поблоково."""
    if mode not in ["encrypt", "decrypt"]:
        raise ValueError("Режим має бути 'encrypt' або 'decrypt'")

    binary_input = (
        text_to_binary(text) if mode == "encrypt" else text
    )  # Для розшифрування вхід вже бінарний

    if len(binary_input) % 8 != 0 and mode == "encrypt":
        # Доповнення останнього блоку нулями (простий варіант)
        # У реальних системах використовують складніші схеми доповнення (padding)
        padding_len = 8 - (len(binary_input) % 8)
        binary_input += "0" * padding_len
        print(
            f"Попередження: Текст доповнено {padding_len} нульовими бітами до кратності 8.",
            file=sys.stderr,
        )

    if len(binary_input) % 8 != 0 and mode == "decrypt":
        print(
            "Помилка: Довжина двійкового шифротексту для розшифрування не кратна 8.",
            file=sys.stderr,
        )
        return None  # Або кинути виняток

    binary_output = ""
    operation = encrypt_block if mode == "encrypt" else decrypt_block

    for i in range(0, len(binary_input), 8):
        block = binary_input[i : i + 8]
        processed_block = operation(block, key_10bit, S0, S1)
        binary_output += processed_block

    if mode == "encrypt":
        return binary_output  # Повертаємо бінарний шифротекст
    else:
        # При розшифруванні намагаємось перетворити результат на текст
        # і видалити можливе доповнення (якщо воно було нулями)
        decrypted_text = binary_to_text(binary_output)
        # Просте видалення нульових символів в кінці (якщо використовувалось доповнення нулями)
        # УВАГА: Це може видалити і корисні нульові символи, якщо вони були в оригіналі!
        # Краще використовувати стандартні схеми padding/unpadding.
        # return decrypted_text.rstrip('\x00')
        return decrypted_text  # Повертаємо текст як є, з можливими доповненнями


if __name__ == "__main__":
    print("--- Система шифрування S-DES ---")

    # Приклад з теоретичних відомостей для перевірки генерації ключів
    example_key = "1010000010"
    k1_ex, k2_ex = generate_keys(example_key)
    print(f"\nПеревірка генерації ключів для {example_key}:")
    print(f"  K1 (очікується 10100100): {k1_ex}")
    print(f"  K2 (очікується 01000011): {k2_ex}")
    assert k1_ex == "10100100"
    assert k2_ex == "01000011"
    print("  Генерація ключів вірна.")

    while True:
        try:
            key = input("\nВведіть 10-бітний ключ (напр., 1010000010): ")
            # Перевірка ключа відбувається в generate_keys, але можна додати тут
            if len(key) != 10 or not all(c in "01" for c in key):
                print("Помилка: Ключ повинен містити рівно 10 бітів (0 або 1).")
                continue
            # Перевірка генерації ключів для введеного ключа
            k1, k2 = generate_keys(key)
            print(f"  Згенеровані підключі: K1={k1}, K2={k2}")
            break
        except ValueError as e:
            print(f"Помилка: {e}")
        except Exception as e:
            print(f"Неочікувана помилка при обробці ключа: {e}")

    while True:
        choice = input(
            "\nОберіть дію:\n1. Шифрувати текст\n2. Розшифрувати текст (бінарний рядок)\n3. Вихід\nВаш вибір: "
        )

        if choice == "1":
            plaintext = input("Введіть текст для шифрування: ")
            try:
                ciphertext_bin = process_text(plaintext, key, "encrypt")
                print(f"\nВідкритий текст: '{plaintext}'")
                print(f"Ключ:           {key}")
                print(f"Шифротекст (бінарний): {ciphertext_bin}")
                # Додатково покажемо, як він може виглядати у вигляді символів (може бути нечитабельним)
                print(
                    f"Шифротекст (символьний вигляд, може бути нечитабельним): '{binary_to_text(ciphertext_bin)}'"
                )
            except Exception as e:
                print(f"Помилка під час шифрування: {e}")

        elif choice == "2":
            ciphertext_bin = input("Введіть шифротекст (бінарний рядок, кратний 8): ")
            if len(ciphertext_bin) % 8 != 0 or not all(
                c in "01" for c in ciphertext_bin
            ):
                print(
                    "Помилка: Шифротекст має бути двійковим рядком, довжина якого кратна 8."
                )
                continue
            try:
                decrypted_text = process_text(ciphertext_bin, key, "decrypt")
                if decrypted_text is not None:
                    print(f"\nШифротекст (бінарний): {ciphertext_bin}")
                    print(f"Ключ:                 {key}")
                    print(f"Розшифрований текст: '{decrypted_text}'")
            except Exception as e:
                print(f"Помилка під час розшифрування: {e}")

        elif choice == "3":
            print("Завершення роботи.")
            break
        else:
            print("Невірний вибір. Спробуйте ще раз.")
