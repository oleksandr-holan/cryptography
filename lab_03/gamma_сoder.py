import sys

ALPHABET = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
MODULUS = 33

LETTER_TO_NUM = {letter: i for i, letter in enumerate(ALPHABET)}
NUM_TO_LETTER = {i: letter for i, letter in enumerate(ALPHABET)}

def generate_gamma(key, length):
    """
    Генерує псевдовипадкову гамму Z на основі ключа Y.
    key: список або кортеж з 3 цілих чисел (Y1, Y2, Y3).
    length: необхідна довжина гамми (довжина повідомлення).
    """
    if len(key) != 3:
        raise ValueError("Ключ повинен складатися з 3 чисел.")

    Y = list(key) # Робимо копію, щоб не змінювати оригінальний ключ

    # Генеруємо послідовність Y до потрібної довжини (length + 1 елементів Y для length елементів Z)
    # Використовуємо 0-базовану індексацію Python, тому Yt -> Y[t-1]
    # Yt = (Yt-1 + Yt-3) mod 32  для t > 3
    # Y[t-1] = (Y[t-2] + Y[t-4]) % MODULUS для t-1 >= 3
    for i in range(3, length + 1): # Нам потрібно Y[length], щоб обчислити Z[length-1]
        try:
            # Y[i] = (Y[i-1] + Y[i-3]) % MODULUS
            new_y = (Y[i-1] + Y[i-3]) % MODULUS
            Y.append(new_y)
        except IndexError:
            print(f"Помилка індексації при генерації Y на кроці {i}. Довжина Y: {len(Y)}")
            # Це може статися, якщо length < 3, але ми генеруємо Z довжиною length
            # Якщо length=1, нам потрібні Y[0], Y[1]. Якщо length=2, Y[0], Y[1], Y[2].
            # Якщо length=3, Y[0], Y[1], Y[2], Y[3].
            # Формула Yt застосовується для t > 3, тобто для Y[3] і далі.
            # Якщо length < 3, цикл for i in range(3, length + 1) не виконається, що коректно.
            break # Виходимо, якщо Y вже достатньо довгий для коротких повідомлень

    # Генеруємо послідовність Z (гамму)
    # Zt = (Yt + Yt+1) mod 32 для t=1,...,n
    # Z[t-1] = (Y[t-1] + Y[t]) % MODULUS для t=1,...,n
    Z = []
    for t in range(length): # t йде від 0 до length-1
        try:
            # Z[t] = (Y[t] + Y[t+1]) % MODULUS
            z_val = (Y[t] + Y[t+1]) % MODULUS
            Z.append(z_val)
        except IndexError:
            print(f"Помилка індексації при генерації Z на кроці {t}. Довжина Y: {len(Y)}, Потрібні індекси: {t}, {t+1}")
            # Це не повинно статися, якщо Y згенеровано правильно до length+1
            break

    if len(Z) != length:
         raise RuntimeError(f"Не вдалося згенерувати гамму потрібної довжини. Отримано {len(Z)}, потрібно {length}")

    return Z

def encrypt(plaintext, key):
    """
    Шифрує відкритий текст за допомогою шифру гаммування.
    plaintext: рядок відкритого тексту.
    key: ключ (список або кортеж з 3 чисел).
    """
    plaintext = plaintext.upper() # Переводимо в верхній регістр
    valid_plaintext = "".join(c for c in plaintext if c in LETTER_TO_NUM) # Фільтруємо тільки літери алфавіту

    if not valid_plaintext:
        return "" # Повертаємо порожній рядок, якщо немає валідних символів

    gamma = generate_gamma(key, len(valid_plaintext))
    ciphertext = ""

    for i, char in enumerate(valid_plaintext):
        t_num = LETTER_TO_NUM[char]
        k_num = gamma[i]
        # si = (C(ti) + ki) mod 32
        s_num = (t_num + k_num) % MODULUS
        ciphertext += NUM_TO_LETTER[s_num]

    return ciphertext

def decrypt(ciphertext, key):
    """
    Розшифровує шифротекст за допомогою шифру гаммування.
    ciphertext: рядок шифротексту.
    key: ключ (список або кортеж з 3 чисел).
    """
    ciphertext = ciphertext.upper() # На випадок, якщо файл містить малі літери
    valid_ciphertext = "".join(c for c in ciphertext if c in LETTER_TO_NUM)

    if not valid_ciphertext:
        return ""

    gamma = generate_gamma(key, len(valid_ciphertext))
    plaintext = ""

    for i, char in enumerate(valid_ciphertext):
        s_num = LETTER_TO_NUM[char]
        k_num = gamma[i]
        # ti = C-1((si + (32 - ki)) mod 32)
        t_num = (s_num + (MODULUS - k_num)) % MODULUS
        plaintext += NUM_TO_LETTER[t_num]

    return plaintext

def main():
    print("--- Система шифрування/розшифрування (Шифр Гаммування) ---")

    while True:
        mode = input("Виберіть режим ('e' - шифрування, 'd' - розшифрування, 'q' - вихід): ").lower()
        if mode in ['e', 'd']:
            break
        elif mode == 'q':
            sys.exit("Вихід з програми.")
        else:
            print("Неправильний режим. Спробуйте ще раз.")

    # Отримання шляхів до файлів
    input_filename = input("Введіть ім'я вхідного файлу: ")
    output_filename = input("Введіть ім'я вихідного файлу: ")

    # Отримання ключа
    while True:
        try:
            key_str = input("Введіть секретний ключ (3 цілих числа через пробіл, напр. '4 31 15'): ")
            key = [int(k) for k in key_str.split()]
            if len(key) == 3 and all(0 <= k < MODULUS for k in key): # Перевірка діапазону 0..31
                break
            else:
                 print(f"Помилка: Ключ повинен складатися з 3 цілих чисел від 0 до {MODULUS-1}.")
        except ValueError:
            print("Помилка: Введіть ключ як 3 цілих числа через пробіл.")

    # Читання з файлу
    try:
        with open(input_filename, 'r', encoding='utf-8') as f_in:
            text_content = f_in.read()
            print(f"\nВміст файлу '{input_filename}':\n{text_content[:200]}...") # Покажемо початок
    except FileNotFoundError:
        print(f"Помилка: Файл '{input_filename}' не знайдено.")
        sys.exit(1)
    except Exception as e:
        print(f"Помилка при читанні файлу '{input_filename}': {e}")
        sys.exit(1)

    # Виконання шифрування або розшифрування
    result_text = ""
    original_valid_len = len("".join(c for c in text_content.upper() if c in LETTER_TO_NUM))

    if mode == 'e':
        print("\n--- Шифрування ---")
        result_text = encrypt(text_content, key)
        print(f"Довжина валідного тексту для шифрування: {original_valid_len}")
        print(f"Довжина згенерованої гамми: {original_valid_len}") # Довжина гамми = довжині валідного тексту
        print(f"Довжина шифрограми: {len(result_text)}")
    elif mode == 'd':
        print("\n--- Розшифрування ---")
        result_text = decrypt(text_content, key)
        print(f"Довжина валідного тексту для розшифрування: {original_valid_len}")
        print(f"Довжина згенерованої гамми: {original_valid_len}")
        print(f"Довжина розшифрованого тексту: {len(result_text)}")


    # Запис результату у файл та вивід на екран
    try:
        with open(output_filename, 'w', encoding='utf-8') as f_out:
            f_out.write(result_text)
        print(f"\nРезультат записано у файл '{output_filename}'.")
        print("\n--- Результат ---")
        print(result_text)
        print("-----------------")

    except Exception as e:
        print(f"Помилка при записі у файл '{output_filename}': {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()