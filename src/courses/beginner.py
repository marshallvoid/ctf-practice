import base64

import pwn
from Crypto.Util.number import *

from src.utils import run_prefixed_functions


def course1() -> str:
    ords = [81, 64, 75, 66, 70, 93, 73, 72, 1, 92, 109, 2, 84, 109, 66, 75, 70, 90, 2, 92, 79]
    return "".join(chr(value ^ 0x32) for value in ords)


def course2() -> str:  # ASCII
    ords = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
    return "".join(chr(value) for value in ords)


def course3() -> str:  # Hex
    cipher_text = "63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"
    return bytes.fromhex(cipher_text).decode()


def course4() -> str:  # Base64
    cipher_text = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"
    return base64.b64encode(bytes.fromhex(cipher_text)).decode()


def course5() -> str:  # Bytes and Big Integers
    value = 11515195063862318899931685488813747395775516287289682636499965282714637259206269
    return long_to_bytes(value).decode()


def course6(strategy: int = 1) -> str:  # XOR
    original = "label"
    key = 13

    if strategy == 1:
        return "".join(chr(ord(ch) ^ key) for ch in original)  # xor operator

    if strategy == 2:
        return pwn.xor(original, key).decode()

    return "Unknown strategy"


def course7(strategy: int = 1) -> str:  # Commutative, Associative, Identity, Self-Inverse
    """
    Commutative: A ⊕ B = B ⊕ A
    Associative: A ⊕ (B ⊕ C) = (A ⊕ B) ⊕ C
    Identity: A ⊕ 0 = A
    Self-Inverse: A ⊕ A = 0

    Problem:
    KEY1 = a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313
    KEY2 ^ KEY1 = 37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e
    KEY2 ^ KEY3 = c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1
    FLAG ^ KEY1 ^ KEY3 ^ KEY2 = 04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf

    Solution:
    D = FLAG ^ KEY1 ^ KEY3 ^ KEY2 = 04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf
    C = KEY2 ^ KEY3 = c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1
    FLAG = D ^ KEY1 ^ C
    """

    if strategy == 1:
        key_d = bytes.fromhex("04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf")
        key1 = bytes.fromhex("a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313")
        key2_3 = bytes.fromhex("c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1")

        flag = pwn.xor(key_d, key1, key2_3)
        return flag.decode()

    if strategy == 2:
        key_d = 0x04EE9855208A2CD59091D04767AE47963170D1660DF7F56F5FAF
        key1 = 0xA6C8B6733C9B22DE7BC0253266A3867DF55ACDE8635E19C73313
        key2_3 = 0xC1545756687E7573DB23AA1C3452A098B71A7FBF0FDDDDDE5FC1

        flag = key_d ^ key1 ^ key2_3
        return long_to_bytes(flag).decode()

    return "Unknown strategy"


def course8() -> str:  # Favorite Byte
    cipher_text = "73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d"
    cipher_bytes = bytes.fromhex(cipher_text)

    for i in range(256):
        flag = pwn.xor(cipher_bytes, i)
        if b"crypto" in flag:
            return flag.decode()

    return "Unknown flag"


def course9() -> str:
    cipher_text = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"
    cipher_bytes = bytes.fromhex(cipher_text)

    part_flag_1 = "crypto{".encode()
    part_flag_2 = "}".encode()

    part_key_1 = pwn.xor(cipher_bytes[:7], part_flag_1)
    part_key_2 = pwn.xor(cipher_bytes[-1], part_flag_2)
    key_bytes = part_key_1 + part_key_2

    flag = pwn.xor(cipher_bytes, key_bytes)
    return flag.decode()


def courses() -> None:
    run_prefixed_functions(namespace=globals(), prefix="course", label="course", copy_last=True)


if __name__ == "__main__":
    courses()
