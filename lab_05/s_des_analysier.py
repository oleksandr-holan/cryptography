import copy
import time

from lab_04.s_des_coders import (
    S0,
    S1,
    decrypt_block,
    encrypt_block,
)


# --- Функції для дослідження розсіювальних властивостей ---
def hamming_distance(bits1, bits2):
    """Обчислює відстань Геммінга між двома бітовими рядками."""
    if len(bits1) != len(bits2):
        raise ValueError("Рядки повинні мати однакову довжину")
    return sum(b1 != b2 for b1, b2 in zip(bits1, bits2))


def flip_bit(bits, position):
    """Інвертує біт у вказаній позиції."""
    bits_list = list(bits)
    bits_list[position] = "1" if bits_list[position] == "0" else "0"
    return "".join(bits_list)


def analyze_key_avalanche(plaintext, key_base):
    """Аналізує лавинний ефект при зміні кожного біта ключа."""
    results = []
    base_cipher = encrypt_block(plaintext, key_base, S0, S1)

    print("\nАналіз лавинного ефекту зміни бітів ключа:")
    print(f"Базовий ключ: {key_base}")
    print(f"Відкритий текст: {plaintext}")
    print(f"Базовий шифротекст: {base_cipher}")

    max_change_bit = -1
    min_change_bit = -1
    max_changes = -1
    min_changes = float("inf")

    for i in range(10):
        modified_key = flip_bit(key_base, i)
        modified_cipher = encrypt_block(plaintext, modified_key, S0, S1)
        distance = hamming_distance(base_cipher, modified_cipher)

        results.append((i, distance))
        print(
            f"Зміна біту {i}: Ключ {modified_key}, Шифротекст {modified_cipher}, Змінено бітів: {distance}"
        )

        # Відстеження бітів з максимальними і мінімальними змінами
        if distance > max_changes:
            max_changes = distance
            max_change_bit = i
        if distance < min_changes:
            min_changes = distance
            min_change_bit = i

    avg_changes = calculate_average_changes(results)
    print(
        f"Середня кількість змінених бітів: {avg_changes:.2f} з 8 (або {avg_changes / 8 * 100:.2f}%)"
    )
    print(
        f"Найбільший вплив має зміна біту {max_change_bit} ключа: {max_changes} змінених бітів"
    )
    print(
        f"Найменший вплив має зміна біту {min_change_bit} ключа: {min_changes} змінених бітів"
    )

    return {
        "results": results,
        "avg_changes": avg_changes,
        "max_bit": max_change_bit,
        "max_changes": max_changes,
        "min_bit": min_change_bit,
        "min_changes": min_changes,
    }


def analyze_plaintext_avalanche(plaintext_base, key):
    """Аналізує лавинний ефект при зміні кожного біта відкритого тексту."""
    results = []
    base_cipher = encrypt_block(plaintext_base, key, S0, S1)

    print("\nАналіз лавинного ефекту зміни бітів відкритого тексту:")
    print(f"Базовий текст: {plaintext_base}")
    print(f"Ключ: {key}")
    print(f"Базовий шифротекст: {base_cipher}")

    max_change_bit = -1
    min_change_bit = -1
    max_changes = -1
    min_changes = float("inf")

    for i in range(8):
        modified_text = flip_bit(plaintext_base, i)
        modified_cipher = encrypt_block(modified_text, key, S0, S1)
        distance = hamming_distance(base_cipher, modified_cipher)

        results.append((i, distance))
        print(
            f"Зміна біту {i}: Текст {modified_text}, Шифротекст {modified_cipher}, Змінено бітів: {distance}"
        )

        # Відстеження бітів з максимальними і мінімальними змінами
        if distance > max_changes:
            max_changes = distance
            max_change_bit = i
        if distance < min_changes:
            min_changes = distance
            min_change_bit = i

    avg_changes = calculate_average_changes(results)
    print(
        f"Середня кількість змінених бітів: {avg_changes:.2f} з 8 (або {avg_changes / 8 * 100:.2f}%)"
    )
    print(
        f"Найбільший вплив має зміна біту {max_change_bit} тексту: {max_changes} змінених бітів"
    )
    print(
        f"Найменший вплив має зміна біту {min_change_bit} тексту: {min_changes} змінених бітів"
    )

    return {
        "results": results,
        "avg_changes": avg_changes,
        "max_bit": max_change_bit,
        "max_changes": max_changes,
        "min_bit": min_change_bit,
        "min_changes": min_changes,
    }


def modify_sbox(sbox, row, col, new_value):
    """Змінює значення у вказаній позиції S-блоку."""
    if not (0 <= row < 4 and 0 <= col < 4 and 0 <= new_value < 4):
        raise ValueError("Неправильні параметри для зміни S-блоку")

    modified_sbox = copy.deepcopy(sbox)
    modified_sbox[row][col] = new_value
    return modified_sbox


def analyze_sbox_changes(plaintext, key, original_s0, original_s1):
    """Аналізує вплив зміни S-блоків на шифрування."""
    # Отримуємо базовий шифротекст з оригінальними S-блоками
    base_cipher = encrypt_block(plaintext, key, original_s0, original_s1)
    print("\nАналіз впливу зміни S-блоків:")
    print(f"Відкритий текст: {plaintext}")
    print(f"Ключ: {key}")
    print(f"Базовий шифротекст: {base_cipher}")

    results = []

    # Тестуємо зміни для S0
    for row in range(4):
        for col in range(4):
            for new_val in range(4):
                if original_s0[row][col] == new_val:
                    continue  # Пропускаємо, якщо значення не змінилося

                # Створюємо копію S0 і змінюємо її
                modified_s0 = [r[:] for r in original_s0]
                modified_s0[row][col] = new_val

                try:
                    modified_cipher = encrypt_block(
                        plaintext, key, modified_s0, original_s1
                    )
                    distance = hamming_distance(base_cipher, modified_cipher)

                    results.append(
                        {
                            "sbox": "S0",
                            "row": row,
                            "col": col,
                            "old_val": original_s0[row][col],
                            "new_val": new_val,
                            "distance": distance,
                            "cipher": modified_cipher,
                        }
                    )

                    print(
                        f"S0[{row}][{col}] {original_s0[row][col]} -> {new_val}: Шифротекст {modified_cipher}, Змінено бітів: {distance}"
                    )
                except Exception as e:
                    print(f"Помилка при зміні S0[{row}][{col}]: {e}")

    # Тестуємо зміни для S1
    for row in range(4):
        for col in range(4):
            for new_val in range(4):
                if original_s1[row][col] == new_val:
                    continue  # Пропускаємо, якщо значення не змінилося

                # Створюємо копію S1 і змінюємо її
                modified_s1 = [r[:] for r in original_s1]
                modified_s1[row][col] = new_val

                try:
                    modified_cipher = encrypt_block(
                        plaintext, key, original_s0, modified_s1
                    )
                    distance = hamming_distance(base_cipher, modified_cipher)

                    results.append(
                        {
                            "sbox": "S1",
                            "row": row,
                            "col": col,
                            "old_val": original_s1[row][col],
                            "new_val": new_val,
                            "distance": distance,
                            "cipher": modified_cipher,
                        }
                    )

                    print(
                        f"S1[{row}][{col}] {original_s1[row][col]} -> {new_val}: Шифротекст {modified_cipher}, Змінено бітів: {distance}"
                    )
                except Exception as e:
                    print(f"Помилка при зміні S1[{row}][{col}]: {e}")

    return results


def brute_force_attack(plaintext, ciphertext, max_keys=1024):
    """Виконує атаку повним перебором ключів."""
    print("\nПочинаємо атаку повним перебором...")
    print(f"Відкритий текст: {plaintext}")
    print(f"Шифротекст: {ciphertext}")

    start_time = time.time()
    keys_tried = 0

    found_keys = []

    for i in range(max_keys):
        key = format(i, "010b")  # Перетворюємо число на 10-бітний ключ
        keys_tried += 1

        try:
            decrypted = decrypt_block(ciphertext, key, S0, S1)
            if decrypted == plaintext:
                found_keys.append(key)
                print(f"Знайдено ключ: {key} після перебору {keys_tried} ключів")
                break  # Знайшли правильний ключ, можемо зупинитись
        except Exception as e:
            print(f"Помилка з ключем {key}: {e}")

    elapsed_time = time.time() - start_time

    print(f"Атака завершена за {elapsed_time:.4f} секунд")
    print(f"Перебрано ключів: {keys_tried}")
    print(f"Знайдені ключі: {found_keys or 'Ключі не знайдені'}")

    return {
        "found_keys": found_keys,
        "keys_tried": keys_tried,
        "time_elapsed": elapsed_time,
    }


def measure_encryption_speed(plaintext, key, iterations=10000):
    """Вимірює швидкість шифрування."""
    start_time = time.time()

    for _ in range(iterations):
        encrypt_block(plaintext, key, S0, S1)

    elapsed_time = time.time() - start_time
    speed_blocks_per_sec = iterations / elapsed_time
    speed_mbits_per_sec = (speed_blocks_per_sec * 8) / 1_000_000  # Мегабіти в секунду

    print("\nШвидкість шифрування:")
    print(f"Оброблено {iterations} блоків за {elapsed_time:.4f} секунд")
    print(f"Швидкість: {speed_blocks_per_sec:.2f} блоків/сек")
    print(f"Швидкість: {speed_mbits_per_sec:.4f} Мбіт/сек")

    return speed_mbits_per_sec


def calculate_average_changes(analysis_results):
    """Обчислює середню кількість змінених бітів."""
    total_changes = sum(changes for _, changes in analysis_results)
    return total_changes / len(analysis_results) if analysis_results else 0


def main():
    """Головна функція для виконання досліджень."""
    print("=== Дослідження розсіювальних властивостей S-DES ===")

    # Ключ "0000000000"
    zero_key = "0000000000"
    all_ones_key = "1111111111"
    random_key = "1010000010"  # Можна задати будь-який інший

    # Тексти для шифрування
    zero_text = "00000000"
    all_ones_text = "11111111"
    random_text = "10101010"  # Можна задати будь-який інший

    # Дослідження зміни ключа
    print("\n=== Дослідження 1: Зміна бітів ключа ===")
    print("Використовуємо ключ 0000000000:")
    key_analysis_zero = analyze_key_avalanche(random_text, zero_key)

    print("\nВикористовуємо ключ 1111111111:")
    key_analysis_ones = analyze_key_avalanche(random_text, all_ones_key)

    print("\nВикористовуємо випадковий ключ 1010000010:")
    key_analysis_random = analyze_key_avalanche(random_text, random_key)

    # Дослідження зміни відкритого тексту
    print("\n=== Дослідження 2: Зміна бітів відкритого тексту ===")
    print("Використовуємо текст 00000000:")
    text_analysis_zero = analyze_plaintext_avalanche(zero_text, random_key)

    print("\nВикористовуємо текст 11111111:")
    text_analysis_ones = analyze_plaintext_avalanche(all_ones_text, random_key)

    print("\nВикористовуємо випадковий текст 10101010:")
    text_analysis_random = analyze_plaintext_avalanche(random_text, random_key)

    # Дослідження зміни S-блоків
    print("\n=== Дослідження 3: Зміна структури матриць заміни ===")
    original_s0 = copy.deepcopy(S0)
    original_s1 = copy.deepcopy(S1)

    sbox_results = analyze_sbox_changes(
        random_text, random_key, original_s0, original_s1
    )

    # Знаходимо найбільш і найменш впливові зміни S-блоків
    sbox_max = max(sbox_results, key=lambda x: x["distance"])
    sbox_min = min(sbox_results, key=lambda x: x["distance"])

    print(
        f"\nНайбільший вплив має зміна {sbox_max['sbox']}[{sbox_max['row']}][{sbox_max['col']}] з {sbox_max['old_val']} на {sbox_max['new_val']}: {sbox_max['distance']} змінених бітів"
    )
    print(
        f"Найменший вплив має зміна {sbox_min['sbox']}[{sbox_min['row']}][{sbox_min['col']}] з {sbox_min['old_val']} на {sbox_min['new_val']}: {sbox_min['distance']} змінених бітів"
    )

    # Атака повним перебором
    print("\n=== Дослідження 4: Атака повним перебором ===")
    plaintext = random_text
    key = random_key
    ciphertext = encrypt_block(plaintext, key, original_s0, original_s1)

    brute_force_results = brute_force_attack(plaintext, ciphertext)

    # Вимірювання швидкості шифрування
    print("\n=== Дослідження 5: Швидкість шифрування ===")
    encryption_speed = measure_encryption_speed(random_text, random_key)

    # Висновки
    print("\n=== Висновки ===")
    print("1. Лавинний ефект при зміні ключа:")
    # Порівняємо середні показники зміни бітів для різних ключів
    print("\nПорівняння середніх показників змін для різних ключів:")
    print(f"Нульовий ключ (0000000000): {key_analysis_zero['avg_changes']:.2f} бітів")
    print(f"Одиничний ключ (1111111111): {key_analysis_ones['avg_changes']:.2f} бітів")
    print(
        f"Випадковий ключ (1010000010): {key_analysis_random['avg_changes']:.2f} бітів"
    )

    print("2. Лавинний ефект при зміні відкритого тексту:")
    # Порівняємо середні показники зміни бітів для різних текстів
    print("\nПорівняння середніх показників змін для різних текстів:")
    print(f"Нульовий текст (00000000): {text_analysis_zero['avg_changes']:.2f} бітів")
    print(f"Одиничний текст (11111111): {text_analysis_ones['avg_changes']:.2f} бітів")
    print(
        f"Випадковий текст (10101010): {text_analysis_random['avg_changes']:.2f} бітів"
    )

    print("3. Криптостійкість до атаки повним перебором:")
    print("   Простір ключів: 2^10 = 1024 ключа")
    print(f"   Середній час зламу: {brute_force_results['time_elapsed']:.4f} секунд")


if __name__ == "__main__":
    main()
