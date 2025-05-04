import os
import traceback

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- Налаштування ---
plaintext_base_str = "Голань Олександр Ростиславович"
# Конвертуємо рядок у байти (використовуємо UTF-8)
plaintext_base_bytes = plaintext_base_str.encode("utf-8")

# Ключ шифрування (має бути відповідної довжини для шифру)
# Blowfish: змінна довжина (8-56 байт), використаємо 16 байт (128 біт)
# AES (Rijndael): 16, 24, або 32 байти (128, 192, 256 біт), використаємо 16 байт
# Важливо: Використовуйте однаковий ключ для порівняння режимів одного шифру
key = b"MySecretKey12345"  # 16 байт

# Вектор ініціалізації (IV) - потрібен для CBC, CFB, OFB
# Розмір IV має дорівнювати розміру блоку шифру
# Blowfish: 8 байт (64 біти)
# AES: 16 байт (128 біт)
# Примітка: У реальних системах IV має бути випадковим для кожного шифрування!
#           Для лабораторної роботи використаємо фіксований IV для відтворюваності.
iv_blowfish = os.urandom(8)  # Генеруємо випадковий, але збережемо для розшифрування
iv_aes = os.urandom(16)  # Аналогічно для AES

# Шифри та режими для тестування
ciphers_to_test = {
    "Blowfish": {
        "algorithm": algorithms.Blowfish(key),
        "block_size": 8,
        "iv": iv_blowfish,
    },
    "Rijndael (AES)": {
        "algorithm": algorithms.AES(key),
        "block_size": 16,
        "iv": iv_aes,
    },
}

modes_to_test = {
    "ECB": modes.ECB,
    "CBC": modes.CBC,  # Потребує IV
    "CFB": modes.CFB,  # Потребує IV (CFB8 або CFB зі змінним розміром сегменту теж існують)
    "OFB": modes.OFB,  # Потребує IV
}

# --- Допоміжні функції ---


def prepare_plaintext(base_bytes, block_size):
    """Готує відкритий текст: доповнює та повторює перші блоки"""
    # Доповнення PKCS7 для вирівнювання по блоку
    padder = padding.PKCS7(block_size * 8).padder()
    padded_data = padder.update(base_bytes) + padder.finalize()

    # Переконуємося, що є хоча б 4 блоки
    min_len = block_size * 4
    while len(padded_data) < min_len:
        padded_data += padded_data[:block_size]  # Додаємо копії першого блоку

    # Робимо перші 4 блоки однаковими
    first_block = padded_data[:block_size]
    modified_data = first_block * 4 + padded_data[block_size * 4 :]

    # Перевірка: переконаємося, що довжина кратна розміру блоку
    # Це важливо для деяких операцій, хоча паддінг вже мав це зробити
    if len(modified_data) % block_size != 0:
        # Додаткове доповнення, якщо раптом щось пішло не так
        padder = padding.PKCS7(block_size * 8).padder()
        modified_data = padder.update(modified_data) + padder.finalize()

    print(
        f"   Підготовлений текст (довжина {len(modified_data)} байт): {modified_data.hex()}"
    )
    return modified_data


def encrypt(algorithm, mode_class, iv, plaintext, block_size):
    """Шифрує дані"""
    backend = default_backend()
    actual_mode = mode_class(iv) if iv else mode_class()  # Створюємо екземпляр режиму
    cipher = Cipher(algorithm, actual_mode, backend=backend)
    encryptor = cipher.encryptor()

    # Для режимів, що не потребують паддінгу на рівні бібліотеки (CFB, OFB)
    # або якщо ми вже вирівняли текст
    if isinstance(actual_mode, (modes.CFB, modes.OFB)):
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    else:  # ECB, CBC - використовуємо паддінг PKCS7
        padder = padding.PKCS7(algorithm.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext


def decrypt(algorithm, mode_class, iv, ciphertext, block_size):
    """Розшифровує дані"""
    backend = default_backend()
    actual_mode = mode_class(iv) if iv else mode_class()  # Створюємо екземпляр режиму
    cipher = Cipher(algorithm, actual_mode, backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Для режимів, що використовували паддінг при шифруванні
    if isinstance(actual_mode, (modes.ECB, modes.CBC)):
        try:
            unpadder = padding.PKCS7(algorithm.block_size).unpadder()
            decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
        except ValueError:
            # Помилка розпакування - ймовірно через пошкодження даних
            print(
                "      ПОМИЛКА: Не вдалося зняти паддінг. Ймовірно, останній блок пошкоджено."
            )
            return decrypted_padded  # Повертаємо як є, щоб бачити пошкодження
    else:  # CFB, OFB - паддінг не застосовувався на цьому рівні
        decrypted_data = decrypted_padded

    return decrypted_data


def introduce_error(ciphertext, block_index, block_size):
    """Вносить помилку (зміна одного біта) в зазначений блок шифротексту"""
    byte_index = block_index * block_size
    if byte_index >= len(ciphertext):
        print(
            f"      ПОПЕРЕДЖЕННЯ: Індекс блоку {block_index} виходить за межі шифротексту (довжина {len(ciphertext)} байт). Помилку не внесено."
        )
        return ciphertext

    # Копіюємо шифротекст, щоб не змінити оригінал
    list_bytes = list(ciphertext)
    original_byte = list_bytes[byte_index]
    # Змінюємо перший біт першого байта блоку
    corrupted_byte = original_byte ^ 0b00000001  # XOR з 1 інвертує останній біт
    # corrupted_byte = original_byte ^ 0b10000000 # XOR з 128 інвертує перший біт

    list_bytes[byte_index] = corrupted_byte
    corrupted_ciphertext = bytes(list_bytes)
    print(
        f"   Внесено помилку в блок {block_index} (байт {byte_index}): {original_byte:02x} -> {corrupted_byte:02x}"
    )
    return corrupted_ciphertext


def compare_data(data1, data2):
    """Порівнює два байти і показує відмінності"""
    diff_count = 0
    len1, len2 = len(data1), len(data2)
    max_len = max(len1, len2)
    diff_map = ["  "] * max_len  # 'vv' - different, '  ' - same

    for i in range(max_len):
        byte1 = data1[i] if i < len1 else None
        byte2 = data2[i] if i < len2 else None
        if byte1 != byte2:
            diff_map[i] = "vv"
            diff_count += 1

    print(f"   Розшифрований оригінал ({len1} байт): {data1.hex()}")
    print(f"   Розшифр. з помилкою ({len2} байт): {data2.hex()}")
    print(f"   Мапа відмінностей      : {''.join(diff_map)}")
    print(f"   Знайдено відмінностей: {diff_count} байт")
    return diff_count


# --- Основний цикл дослідження ---

report = {}  # Словник для зберігання результатів

for cipher_name, cipher_props in ciphers_to_test.items():
    print(
        f"\n===== Шифр: {cipher_name} (Розмір блоку: {cipher_props['block_size']} байт) ====="
    )
    algo = cipher_props["algorithm"]
    block_size = cipher_props["block_size"]
    iv = cipher_props["iv"]  # IV для цього шифру

    # Готуємо plaintext для цього розміру блоку
    original_plaintext = prepare_plaintext(plaintext_base_bytes, block_size)
    num_blocks = len(original_plaintext) // block_size

    report[cipher_name] = {}

    for mode_name, mode_class in modes_to_test.items():
        print(f"\n--- Режим: {mode_name} ---")
        current_iv = iv if mode_name in ["CBC", "CFB", "OFB"] else None
        mode_instance_for_encrypt = (
            mode_class(current_iv) if current_iv else mode_class()
        )
        mode_instance_for_decrypt = (
            mode_class(current_iv) if current_iv else mode_class()
        )

        report[cipher_name][mode_name] = {}

        # 1. Шифрування оригінального тексту
        try:
            original_ciphertext = encrypt(
                algo, mode_class, current_iv, original_plaintext, block_size
            )
            print(
                f"   Оригінальний шифротекст ({len(original_ciphertext)} байт): {original_ciphertext.hex()}"
            )

            # Перевірка ECB на повторювані блоки шифротексту
            if mode_name == "ECB":
                print("   Аналіз ECB:")
                blocks = [
                    original_ciphertext[i : i + block_size]
                    for i in range(0, len(original_ciphertext), block_size)
                ]
                if blocks[0] == blocks[1] == blocks[2] == blocks[3]:
                    print(
                        "      УВАГА: Перші 4 блоки шифротексту ОДНАКОВІ, як і очікувалося для ECB з однаковими блоками відкритого тексту."
                    )
                else:
                    print(
                        "      ПОМИЛКА?: Перші 4 блоки шифротексту НЕ однакові для ECB."
                    )

            # 2. Розшифрування оригінального шифротексту (контроль)
            decrypted_original = decrypt(
                algo, mode_class, current_iv, original_ciphertext, block_size
            )
            if decrypted_original == original_plaintext:
                print("   Контрольне розшифрування: Успішно.")
            else:
                print("   ПОМИЛКА КОНТРОЛЬНОГО РОЗШИФРУВАННЯ!")
                print(f"      Очікувалося: {original_plaintext.hex()}")
                print(f"      Отримано  : {decrypted_original.hex()}")
                continue  # Пропускаємо аналіз помилок для цього режиму/шифру

            # 3. Внесення помилок та аналіз
            # Блоки для зміни: 0, 1, передостанній, останній
            blocks_to_modify_indices = {0, 1}
            if num_blocks > 1:
                blocks_to_modify_indices.add(num_blocks - 2)  # Передостанній
                blocks_to_modify_indices.add(num_blocks - 1)  # Останній
            # Перетворюємо в відсортований список унікальних індексів
            blocks_to_modify = sorted(list(blocks_to_modify_indices))
            # Обмеження, якщо блоків менше 4
            blocks_to_modify = [idx for idx in blocks_to_modify if idx < num_blocks]

            print(f"   Аналіз поширення помилки (блоки {blocks_to_modify}):")
            results = {}
            for block_idx in blocks_to_modify:
                print(f"   -> Зміна блоку {block_idx}:")
                corrupted_ciphertext = introduce_error(
                    original_ciphertext, block_idx, block_size
                )
                print(
                    f"      Пошкоджений шифротекст ({len(corrupted_ciphertext)} байт): {corrupted_ciphertext.hex()}"
                )

                # Розшифровуємо пошкоджений текст
                decrypted_corrupted = decrypt(
                    algo, mode_class, current_iv, corrupted_ciphertext, block_size
                )

                # Порівнюємо результат з оригінальним відкритим текстом
                diff_count = compare_data(original_plaintext, decrypted_corrupted)
                results[block_idx] = diff_count

            report[cipher_name][mode_name]["error_propagation"] = results
            report[cipher_name][mode_name]["ciphertext_sample"] = (
                original_ciphertext.hex()[:64]
            )  # Зразок шифротексту
            report[cipher_name][mode_name]["plaintext_sample"] = (
                original_plaintext.hex()[:64]
            )  # Зразок відкритого тексту

        except Exception as e:
            print(f"   ПОМИЛКА під час обробки {cipher_name} / {mode_name}: {repr(e)}")
            # Додатково можна вивести traceback для повного відлагодження (розкоментуйте, якщо потрібно)
            traceback.print_exc()
            report[cipher_name][mode_name] = {"error": str(e)}


# --- Звіт ---
print("\n\n===== Підсумковий звіт аналізу поширення помилок =====")

for cipher_name, modes_data in report.items():
    print(f"\n--- Шифр: {cipher_name} ---")
    print(
        f"   Зразок відкритого тексту: {modes_data.get(next(iter(modes_data)), {}).get('plaintext_sample', 'N/A')}..."
    )
    for mode_name, results in modes_data.items():
        print(f"  Режим: {mode_name}")
        if "error" in results:
            print(f"    Помилка обробки: {results['error']}")
        elif "error_propagation" in results:
            print(
                f"    Зразок шифротексту: {results.get('ciphertext_sample', 'N/A')}..."
            )
            print(
                "    Поширення помилки (кількість змінених байт при зміні 1 біта в блоці X):"
            )
            for block_idx, diff_count in results["error_propagation"].items():
                print(f"      Блок {block_idx}: {diff_count} змінених байт")
        else:
            print("    Немає даних про поширення помилки.")

print("\n===== Завершено =====")
