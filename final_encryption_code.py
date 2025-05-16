import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.backends import default_backend
import base64

# Define a pool of unique characters from various languages
character_pool = [
    'Δ', 'Λ', 'Ξ', 'Π', 'Σ', 'Φ', 'Χ', 'Ψ', 'Ω', 'δ', 'λ', 'ξ', 'π', 'σ', 'φ', 'χ', 'ψ', 'ω',
    'Д', 'Ж', 'З', 'Ц', 'Ч', 'Ш', 'Щ', 'Ъ', 'Ы', 'Ь', 'Э', 'Ю', 'Я', 'д', 'ж', 'з', 'ц', 'ч', 'ш', 'щ', 'ъ', 'ы', 'ь', 'э', 'ю', 'я',
    'あ', 'い', 'う', 'え', 'お', 'か', 'き', 'く', 'け', 'こ', 'さ', 'し', 'す', 'せ', 'そ', 'た', 'ち', 'つ', 'て', 'と',
    'ث', 'ح', 'خ', 'ذ', 'ز', 'ش', 'ص', 'ض', 'ط', 'ظ', 'ع', 'غ', 'ف', 'ق', 'ك', 'ل', 'م', 'ن', 'ه', 'و', 'ي',
    'ა', 'ბ', 'გ', 'დ', 'ე', 'ვ', 'ზ', 'თ', 'ი', 'კ', 'ლ', 'მ', 'ნ', 'ო', 'პ', 'ჟ', 'რ', 'ს', 'ტ', 'უ', 'ფ', 'ქ', 'ღ', 'ყ', 'შ', 'ჩ', 'ც', 'ძ', 'წ', 'ჭ', 'ხ', 'ჯ', 'ჰ',
    'அ', 'ஆ', 'இ', 'ஈ', 'உ', 'ஊ', 'எ', 'ஏ', 'ஐ', 'ஒ', 'ஓ', 'ஔ', 'க', 'ங', 'ச', 'ஜ', 'ஞ', 'ட', 'ண', 'த', 'ந', 'ன', 'ப', 'ம', 'ய', 'ர', 'ல', 'ள', 'ழ', 'வ', 'ஷ', 'ஸ', 'ஹ',
    'ก', 'ข', 'ฃ', 'ค', 'ฅ', 'ฆ', 'ง', 'จ', 'ฉ', 'ช', 'ซ', 'ฌ', 'ญ', 'ฎ', 'ฏ', 'ฐ', 'ฑ', 'ฒ', 'ณ', 'ด', 'ต', 'ถ', 'ท', 'ธ', 'น', 'บ', 'ป', 'ผ', 'ฝ', 'พ', 'ฟ', 'ภ', 'ม', 'ย', 'ร', 'ฤ', 'ล', 'ฦ', 'ว', 'ศ', 'ษ', 'ส', 'ห', 'ฬ', 'อ', 'ฮ',
    'Ա', 'Բ', 'Գ', 'Դ', 'Ե', 'Զ', 'Է', 'Ը', 'Թ', 'Ժ', 'Ի', 'Լ', 'Խ', 'Ծ', 'Կ', 'Հ', 'Ձ', 'Ղ', 'Ճ', 'Մ', 'Յ', 'Ն', 'Շ', 'Ո', 'Չ', 'Պ', 'Ջ', 'Ռ', 'Ս', 'Վ', 'Տ', 'Ր', 'Ց', 'Փ', 'Ք', 'Օ', 'Ֆ',
    'א', 'ב', 'ג', 'ד', 'ה', 'ו', 'ז', 'ח', 'ט', 'י', 'כ', 'ל', 'מ', 'נ', 'ס', 'ע', 'פ', 'צ', 'ק', 'ר', 'ש', 'ת',
    'ㄱ', 'ㄴ', 'ㄷ', 'ㄹ', 'ㅁ', 'ㅂ', 'ㅅ', 'ㅇ', 'ㅈ', 'ㅊ', 'ㅋ', 'ㅌ', 'ㅍ', 'ㅎ', 'ㅏ', 'ㅑ', 'ㅓ', 'ㅕ', 'ㅗ', 'ㅛ', 'ㅜ', 'ㅠ', 'ㅡ', 'ㅣ',
    'अ', 'आ', 'इ', 'ई', 'उ', 'ऊ', 'ऋ', 'ए', 'ऐ', 'ओ', 'औ', 'क', 'ख', 'ग', 'घ', 'ङ', 'च', 'छ', 'ज', 'झ', 'ञ', 'ट', 'ठ', 'ड', 'ढ', 'ण', 'त', 'थ', 'द', 'ध', 'न', 'प', 'फ', 'ब', 'भ', 'म', 'य', 'र', 'ल', 'व', 'श', 'ष', 'स', 'ह',
    'অ', 'আ', 'ই', 'ঈ', 'উ', 'ঊ', 'ঋ', 'এ', 'ঐ', 'ও', 'ঔ', 'ক', 'খ', 'গ', 'ঘ', 'ঙ', 'চ', 'ছ', 'জ', 'ঝ', 'ঞ', 'ট', 'ঠ', 'ড', 'ঢ', 'ণ', 'ত', 'থ', 'দ', 'ধ', 'ন', 'প', 'ফ', 'ব', 'ভ', 'ম', 'য', 'র', 'ল', 'শ', 'ষ', 'স', 'হ',
    'અ', 'આ', 'ઇ', 'ઈ', 'ઉ', 'ઊ', 'ઋ', 'એ', 'ઐ', 'ઓ', 'ઔ', 'ક', 'ખ', 'ગ', 'ઘ', 'ચ', 'છ', 'જ', 'ઝ', 'ટ', 'ઠ', 'ડ', 'ઢ', 'ત', 'થ', 'દ', 'ધ', 'ન', 'પ', 'ફ', 'બ', 'ભ', 'મ', 'ય', 'ર', 'લ', 'વ', 'શ', 'ષ', 'સ', 'હ',
    'ಅ', 'ಆ', 'ಇ', 'ಈ', 'ಉ', 'ಊ', 'ಋ', 'ಎ', 'ಏ', 'ಐ', 'ಒ', 'ಓ', 'ಔ', 'ಕ', 'ಖ', 'ಗ', 'ಘ', 'ಚ', 'ಜ', 'ಞ', 'ಟ', 'ಠ', 'ಡ', 'ತ', 'ಥ', 'ದ', 'ನ', 'ಪ', 'ಫ', 'ಬ', 'ಭ', 'ಮ', 'ಯ', 'ರ', 'ಲ', 'ವ', 'ಶ', 'ಸ', 'ಹ',
    'అ', 'ఆ', 'ఇ', 'ఈ', 'ఉ', 'ఊ', 'ఋ', 'ఎ', 'ఏ', 'ఐ', 'ఒ', 'ఓ', 'ఔ', 'క', 'గ', 'ఘ', 'చ', 'జ', 'ఞ', 'ట', 'డ', 'త', 'ద', 'న', 'ప', 'బ', 'మ', 'య', 'ర', 'ల', 'వ', 'శ', 'స', 'హ',
    'ཀ', 'ཁ', 'ག', 'ང', 'ཅ', 'ཆ', 'ཇ', 'ཉ', 'ཏ', 'ཐ', 'ད', 'ན', 'པ', 'ཕ', 'བ', 'མ', 'ཙ', 'ཚ', 'ཛ', 'ཝ', 'ཞ', 'ཟ', 'འ', 'ཡ', 'ར', 'ལ', 'ཤ', 'ས', 'ཧ', 'ཨ',
    'ກ', 'ຂ', 'ຄ', 'ງ', 'ຈ', 'ຊ', 'ຍ', 'ດ', 'ຕ', 'ນ', 'ບ', 'ປ', 'ຜ', 'ຝ', 'ພ', 'ຟ', 'ມ', 'ຢ', 'ຣ', 'ລ', 'ວ', 'ສ', 'ຫ', 'ອ',
    'က', 'ခ', 'ဂ', 'ဃ', 'င', 'စ', 'ဆ', 'ဇ', 'ဈ', 'ဉ', 'ည', 'တ', 'ထ', 'ဒ', 'ဓ', 'န', 'ပ', 'ဖ', 'ဗ', 'ဘ', 'မ', 'ယ', 'ရ', 'လ', 'ဝ', 'သ', 'ဟ', 'ဠ', 'အ',
    'ក', 'ខ', 'គ', 'ឃ', 'ង', 'ច', 'ឆ', 'ជ', 'ញ', 'ដ', 'ឋ', 'ឌ', 'ឍ', 'ណ', 'ត', 'ថ', 'ទ', 'ធ', 'ន', 'ប', 'ផ', 'ព', 'ភ', 'ម', 'យ', 'រ', 'ល', 'វ', 'ស', 'ហ', 'អ',
    'අ', 'ආ', 'ඇ', 'ඈ', 'ඉ', 'ඊ', 'උ', 'ඌ', 'එ', 'ඒ', 'ඓ', 'ඔ', 'ඕ', 'ඖ', 'ක', 'ඛ', 'ග', 'ඝ', 'ච', 'ඡ', 'ජ', 'ඣ', 'ට', 'ඨ', 'ඩ', 'ඪ', 'ත', 'ථ', 'ද', 'ධ', 'න', 'ප', 'ඵ', 'බ', 'භ', 'ම', 'ය', 'ර', 'ල', 'ව', 'ශ', 'ෂ', 'ස', 'හ'
]

english_characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

# Multilingual substitution with position-based mappings
def multilingual_substitution(message):
    encrypted_message = []
    key_map = {}
    used_symbols = set()

    for i, char in enumerate(message):
        if char not in key_map:
            key_map[char] = {}
        
        if i in key_map[char]:
            substitute = key_map[char][i]
        else:
            substitute = secrets.choice(character_pool)
            while substitute in used_symbols:
                substitute = secrets.choice(character_pool)
            key_map[char][i] = substitute
            used_symbols.add(substitute)
        
        encrypted_message.append(substitute)

    return ''.join(encrypted_message), key_map

# Reverse multilingual substitution
def reverse_multilingual_substitution(multilingual_message, key_map):
    reversed_message = []

    for i, char in enumerate(multilingual_message):
        for original_char, position_map in key_map.items():
            if position_map.get(i) == char:
                reversed_message.append(original_char)
                break

    return ''.join(reversed_message)

# English substitution
def english_substitution(multilingual_message):
    encrypted_message = []
    english_map = {}
    used_symbols = set()

    for i, char in enumerate(multilingual_message):
        if (char, i) in english_map:
            substitute = english_map[(char, i)]
        else:
            substitute = secrets.choice(english_characters)
            # Ensure the same symbol is not mapped to multiple characters
            while substitute in used_symbols and substitute in english_map.values():
                substitute = secrets.choice(english_characters)
            english_map[(char, i)] = substitute
            used_symbols.add(substitute)
        
        encrypted_message.append(substitute)

    return ''.join(encrypted_message), english_map

# Reverse English substitution
def reverse_english_substitution(english_message, english_map):
    reversed_message = []

    for i, char in enumerate(english_message):
        for (original_char, position), mapped_char in english_map.items():
            if mapped_char == char and position == i:
                reversed_message.append(original_char)
                break

    return ''.join(reversed_message)

# RSA key generation
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# RSA encryption
def rsa_encrypt_aes_key(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# RSA decryption
def rsa_decrypt_aes_key(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# AES encryption
def aes_encrypt(data, password, public_key):
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    aes_key = kdf.derive(password.encode())

    encrypted_aes_key = rsa_encrypt_aes_key(aes_key, public_key)
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(salt + iv + encrypted_aes_key + encrypted_data).decode()

# AES decryption
def aes_decrypt(encrypted_data, password, private_key):
    data = base64.b64decode(encrypted_data)
    salt = data[:16]
    iv = data[16:32]
    encrypted_aes_key = data[32:288]
    encrypted_message = data[288:]

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    aes_key = rsa_decrypt_aes_key(encrypted_aes_key, private_key)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_message) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded_data) + unpadder.finalize()).decode()

# Example usage
if __name__ == "__main__":
    message = input("Enter your message: ")
    password = input("Enter Password for encryption:")

    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    print("Original message:", message)
    
    # Multilingual substitution
    multilingual_message, multilingual_map = multilingual_substitution(message)
    print("After multilingual substitution:", multilingual_message)
    
    # English substitution
    english_message, english_map = english_substitution(multilingual_message)
    print("After English substitution:", english_message)
    
    # AES encryption
    encrypted_message = aes_encrypt(english_message, password, public_key)
    print("After AES encryption:", encrypted_message)

    # Decryption process
    decrypted_english_message = aes_decrypt(encrypted_message, password, private_key)
    print("After AES decryption:", decrypted_english_message)

    reversed_multilingual_message = reverse_english_substitution(decrypted_english_message, english_map)
    print("After reversing English substitution:", reversed_multilingual_message)

    final_message = reverse_multilingual_substitution(reversed_multilingual_message, multilingual_map)
    print("After reversing multilingual substitution:", final_message)
