"""
Эксплуатационная практика МУИВ
Петроградский Вячеслав Максимович
Январь 2026 года
"""

import struct
from typing import Optional, Tuple, List

# Константы алгоритма
MIN_KEY_LEN = 1  # Минимальная длина ключа в байтах
MAX_KEY_LEN = 32  # Максимальная длина ключа в байтах
MAX_IV_LEN = 16  # Максимальная длина IV в байтах
KESTREAM_BLOCK = 80  # Размер блока гаммы в байтах, т.к. 4*4*5 32-битных слов

MASK_32BIT = 0xFFFFFFFF  # Маска для 32-битных операций


def rotate_left(val: int, shift: int) -> int:
    """
    Циклический сдвиг 32-битного числа влево.

    Исходные параметры:
        val: исходное 32-битное число
        shift: количество бит для сдвига (0-31)
    Результат на выходе:
        Число после циклического сдвига
    """
    return ((val << shift) & MASK_32BIT) | ((val & MASK_32BIT) >> (32 - shift))

"""
Таблицы умножения для поля GF(2^8)
Источник: Спецификация алгоритма Sosemanuk (eSTREAM Project)
Документ: "Sosemanuk: A Fast Software-Oriented Stream Cipher"
Авторы: Berbain, Billet, Canteaut, Courtois, Gilbert и др.
Раздел: 2.3 "The Finite Field GF(2^8)"
Неприводимый многочлен: x^8 + x^7 + x^5 + x^3 + 1 (0x1A9)

Обе таблицы взяты из официальной реализации на C:
MulAlpha[256]   - умножение на alpha = 0x02
MulInvAlpha[256] - умножение на inv_alpha = 0x8D
"""

# Таблица умножения alpha в поле GF (2^8)
MUL_ALPHA_TABLE = [
    0x00000000, 0xE19FCF13, 0x6B973726, 0x8A08F835, 0xD6876E4C, 0x3718A15F, 0xBD10596A, 0x5C8F9679,
    0x05A7DC98, 0xE438138B, 0x6E30EBBE, 0x8FAF24AD, 0xD320B2D4, 0x32BF7DC7, 0xB8B785F2, 0x59284AE1,
    0x0AE71199, 0xEB78DE8A, 0x617026BF, 0x80EFE9AC, 0xDC607FD5, 0x3DFFB0C6, 0xB7F748F3, 0x566887E0,
    0x0F40CD01, 0xEEDF0212, 0x64D7FA27, 0x85483534, 0xD9C7A34D, 0x38586C5E, 0xB250946B, 0x53CF5B78,
    0x1467229B, 0xF5F8ED88, 0x7FF015BD, 0x9E6FDAAE, 0xC2E04CD7, 0x237F83C4, 0xA9777BF1, 0x48E8B4E2,
    0x11C0FE03, 0xF05F3110, 0x7A57C925, 0x9BC80636, 0xC747904F, 0x26D85F5C, 0xACD0A769, 0x4D4F687A,
    0x1E803302, 0xFF1FFC11, 0x75170424, 0x9488CB37, 0xC8075D4E, 0x2998925D, 0xA3906A68, 0x420FA57B,
    0x1B27EF9A, 0xFAB82089, 0x70B0D8BC, 0x912F17AF, 0xCDA081D6, 0x2C3F4EC5, 0xA637B6F0, 0x47A879E3,
    0x28CE449F, 0xC9518B8C, 0x435973B9, 0xA2C6BCAA, 0xFE492AD3, 0x1FD6E5C0, 0x95DE1DF5, 0x7441D2E6,
    0x2D699807, 0xCCF65714, 0x46FEAF21, 0xA7616032, 0xFBEEF64B, 0x1A713958, 0x9079C16D, 0x71E60E7E,
    0x22295506, 0xC3B69A15, 0x49BE6220, 0xA821AD33, 0xF4AE3B4A, 0x1531F459, 0x9F390C6C, 0x7EA6C37F,
    0x278E899E, 0xC611468D, 0x4C19BEB8, 0xAD8671AB, 0xF109E7D2, 0x109628C1, 0x9A9ED0F4, 0x7B011FE7,
    0x3CA96604, 0xDD36A917, 0x573E5122, 0xB6A19E31, 0xEA2E0848, 0x0BB1C75B, 0x81B93F6E, 0x6026F07D,
    0x390EBA9C, 0xD891758F, 0x52998DBA, 0xB30642A9, 0xEF89D4D0, 0x0E161BC3, 0x841EE3F6, 0x65812CE5,
    0x364E779D, 0xD7D1B88E, 0x5DD940BB, 0xBC468FA8, 0xE0C919D1, 0x0156D6C2, 0x8B5E2EF7, 0x6AC1E1E4,
    0x33E9AB05, 0xD2766416, 0x587E9C23, 0xB9E15330, 0xE56EC549, 0x04F10A5A, 0x8EF9F26F, 0x6F663D7C,
    0x50358897, 0xB1AA4784, 0x3BA2BFB1, 0xDA3D70A2, 0x86B2E6DB, 0x672D29C8, 0xED25D1FD, 0x0CBA1EEE,
    0x5592540F, 0xB40D9B1C, 0x3E056329, 0xDF9AAC3A, 0x83153A43, 0x628AF550, 0xE8820D65, 0x091DC276,
    0x5AD2990E, 0xBB4D561D, 0x3145AE28, 0xD0DA613B, 0x8C55F742, 0x6DCA3851, 0xE7C2C064, 0x065D0F77,
    0x5F754596, 0xBEEA8A85, 0x34E272B0, 0xD57DBDA3, 0x89F22BDA, 0x686DE4C9, 0xE2651CFC, 0x03FAD3EF,
    0x4452AA0C, 0xA5CD651F, 0x2FC59D2A, 0xCE5A5239, 0x92D5C440, 0x734A0B53, 0xF942F366, 0x18DD3C75,
    0x41F57694, 0xA06AB987, 0x2A6241B2, 0xCBFD8EA1, 0x977218D8, 0x76EDD7CB, 0xFCE52FFE, 0x1D7AE0ED,
    0x4EB5BB95, 0xAF2A7486, 0x25228CB3, 0xC4BD43A0, 0x9832D5D9, 0x79AD1ACA, 0xF3A5E2FF, 0x123A2DEC,
    0x4B12670D, 0xAA8DA81E, 0x2085502B, 0xC11A9F38, 0x9D950941, 0x7C0AC652, 0xF6023E67, 0x179DF174,
    0x78FBCC08, 0x9964031B, 0x136CFB2E, 0xF2F3343D, 0xAE7CA244, 0x4FE36D57, 0xC5EB9562, 0x24745A71,
    0x7D5C1090, 0x9CC3DF83, 0x16CB27B6, 0xF754E8A5, 0xABDB7EDC, 0x4A44B1CF, 0xC04C49FA, 0x21D386E9,
    0x721CDD91, 0x93831282, 0x198BEAB7, 0xF81425A4, 0xA49BB3DD, 0x45047CCE, 0xCF0C84FB, 0x2E934BE8,
    0x77BB0109, 0x9624CE1A, 0x1C2C362F, 0xFDB3F93C, 0xA13C6F45, 0x40A3A056, 0xCAAB5863, 0x2B349770,
    0x6C9CEE93, 0x8D032180, 0x070BD9B5, 0xE69416A6, 0xBA1B80DF, 0x5B844FCC, 0xD18CB7F9, 0x301378EA,
    0x693B320B, 0x88A4FD18, 0x02AC052D, 0xE333CA3E, 0xBFBC5C47, 0x5E239354, 0xD42B6B61, 0x35B4A472,
    0x667BFF0A, 0x87E43019, 0x0DECC82C, 0xEC73073F, 0xB0FC9146, 0x51635E55, 0xDB6BA660, 0x3AF46973,
    0x63DC2392, 0x8243EC81, 0x084B14B4, 0xE9D4DBA7, 0xB55B4DDE, 0x54C482CD, 0xDECC7AF8, 0x3F53B5EB
]

# Таблица умножения 1/alpha в поле GF(2^8)
MUL_INV_ALPHA_TABLE = [
    0x00000000, 0x180F40CD, 0x301E8033, 0x2811C0FE, 0x603CA966, 0x7833E9AB, 0x50222955, 0x482D6998,
    0xC078FBCC, 0xD877BB01, 0xF0667BFF, 0xE8693B32, 0xA04452AA, 0xB84B1267, 0x905AD299, 0x88559254,
    0x29F05F31, 0x31FF1FFC, 0x19EEDF02, 0x01E19FCF, 0x49CCF657, 0x51C3B69A, 0x79D27664, 0x61DD36A9,
    0xE988A4FD, 0xF187E430, 0xD99624CE, 0xC1996403, 0x89B40D9B, 0x91BB4D56, 0xB9AA8DA8, 0xA1A5CD65,
    0x5249BE62, 0x4A46FEAF, 0x62573E51, 0x7A587E9C, 0x32751704, 0x2A7A57C9, 0x026B9737, 0x1A64D7FA,
    0x923145AE, 0x8A3E0563, 0xA22FC59D, 0xBA208550, 0xF20DECC8, 0xEA02AC05, 0xC2136CFB, 0xDA1C2C36,
    0x7BB9E153, 0x63B6A19E, 0x4BA76160, 0x53A821AD, 0x1B854835, 0x038A08F8, 0x2B9BC806, 0x339488CB,
    0xBBC11A9F, 0xA3CE5A52, 0x8BDF9AAC, 0x93D0DA61, 0xDBFDB3F9, 0xC3F2F334, 0xEBE333CA, 0xF3EC7307,
    0xA492D5C4, 0xBC9D9509, 0x948C55F7, 0x8C83153A, 0xC4AE7CA2, 0xDCA13C6F, 0xF4B0FC91, 0xECBFBC5C,
    0x64EA2E08, 0x7CE56EC5, 0x54F4AE3B, 0x4CFBEEF6, 0x04D6876E, 0x1CD9C7A3, 0x34C8075D, 0x2CC74790,
    0x8D628AF5, 0x956DCA38, 0xBD7C0AC6, 0xA5734A0B, 0xED5E2393, 0xF551635E, 0xDD40A3A0, 0xC54FE36D,
    0x4D1A7139, 0x551531F4, 0x7D04F10A, 0x650BB1C7, 0x2D26D85F, 0x35299892, 0x1D38586C, 0x053718A1,
    0xF6DB6BA6, 0xEED42B6B, 0xC6C5EB95, 0xDECAAB58, 0x96E7C2C0, 0x8EE8820D, 0xA6F942F3, 0xBEF6023E,
    0x36A3906A, 0x2EACD0A7, 0x06BD1059, 0x1EB25094, 0x569F390C, 0x4E9079C1, 0x6681B93F, 0x7E8EF9F2,
    0xDF2B3497, 0xC724745A, 0xEF35B4A4, 0xF73AF469, 0xBF179DF1, 0xA718DD3C, 0x8F091DC2, 0x97065D0F,
    0x1F53CF5B, 0x075C8F96, 0x2F4D4F68, 0x37420FA5, 0x7F6F663D, 0x676026F0, 0x4F71E60E, 0x577EA6C3,
    0xE18D0321, 0xF98243EC, 0xD1938312, 0xC99CC3DF, 0x81B1AA47, 0x99BEEA8A, 0xB1AF2A74, 0xA9A06AB9,
    0x21F5F8ED, 0x39FAB820, 0x11EB78DE, 0x09E43813, 0x41C9518B, 0x59C61146, 0x71D7D1B8, 0x69D89175,
    0xC87D5C10, 0xD0721CDD, 0xF863DC23, 0xE06C9CEE, 0xA841F576, 0xB04EB5BB, 0x985F7545, 0x80503588,
    0x0805A7DC, 0x100AE711, 0x381B27EF, 0x20146722, 0x68390EBA, 0x70364E77, 0x58278E89, 0x4028CE44,
    0xB3C4BD43, 0xABCBFD8E, 0x83DA3D70, 0x9BD57DBD, 0xD3F81425, 0xCBF754E8, 0xE3E69416, 0xFBE9D4DB,
    0x73BC468F, 0x6BB30642, 0x43A2C6BC, 0x5BAD8671, 0x1380EFE9, 0x0B8FAF24, 0x239E6FDA, 0x3B912F17,
    0x9A34E272, 0x823BA2BF, 0xAA2A6241, 0xB225228C, 0xFA084B14, 0xE2070BD9, 0xCA16CB27, 0xD2198BEA,
    0x5A4C19BE, 0x42435973, 0x6A52998D, 0x725DD940, 0x3A70B0D8, 0x227FF015, 0x0A6E30EB, 0x12617026,
    0x451FD6E5, 0x5D109628, 0x750156D6, 0x6D0E161B, 0x25237F83, 0x3D2C3F4E, 0x153DFFB0, 0x0D32BF7D,
    0x85672D29, 0x9D686DE4, 0xB579AD1A, 0xAD76EDD7, 0xE55B844F, 0xFD54C482, 0xD545047C, 0xCD4A44B1,
    0x6CEF89D4, 0x74E0C919, 0x5CF109E7, 0x44FE492A, 0x0CD320B2, 0x14DC607F, 0x3CCDA081, 0x24C2E04C,
    0xAC977218, 0xB49832D5, 0x9C89F22B, 0x8486B2E6, 0xCCABDB7E, 0xD4A49BB3, 0xFCB55B4D, 0xE4BA1B80,
    0x17566887, 0x0F59284A, 0x2748E8B4, 0x3F47A879, 0x776AC1E1, 0x6F65812C, 0x477441D2, 0x5F7B011F,
    0xD72E934B, 0xCF21D386, 0xE7301378, 0xFF3F53B5, 0xB7123A2D, 0xAF1D7AE0, 0x870CBA1E, 0x9F03FAD3,
    0x3EA637B6, 0x26A9777B, 0x0EB8B785, 0x16B7F748, 0x5E9A9ED0, 0x4695DE1D, 0x6E841EE3, 0x768B5E2E,
    0xFEDECC7A, 0xE6D18CB7, 0xCEC04C49, 0xD6CF0C84, 0x9EE2651C, 0x86ED25D1, 0xAEFCE52F, 0xB6F3A5E2
]


def multiply_alpha(x: int) -> int:
    """
    Умножение 32-битного числа на alpha в поле GF(2^8).

    Исходный параметр:
        x: исходное 32-битное число
    Результат на выходе:
        Результат умножения на alpha
    """
    return ((x << 8) & MASK_32BIT) ^ MUL_ALPHA_TABLE[x >> 24]


def multiply_inv_alpha(x: int) -> int:
    """
    Умножение 32-битного числа на 1/alpha в поле GF(2^8).

    Исходный параметр:
        x: исходное 32-битное число
    Результат на выходе:
        Результат умножения на 1/alpha
    """
    return (x >> 8) ^ MUL_INV_ALPHA_TABLE[x & 0xFF]


def special_mux(control: int, x: int, y: int) -> int:
    """
    Мультиплексер возвращает x, если control четное, иначе x xor y.

    Исходные параметры:
        control: управляющий бит
        x: первое значение
        y: второе значение
    Результат на выходе:
        x если control&1 == 0, иначе x xor y
    """
    return (x ^ y) if (control & 1) != 0 else x


class CustomSosemanuk:
    """Класс для шифрования/расшифрования"""

    @staticmethod
    def sub_box0(reg: List[int], idx0: int, idx1: int, idx2: int, idx3: int, idx4: int) -> None:
        """S-блок 0 алгоритма Serpent"""
        reg[idx3] ^= reg[idx0]
        reg[idx4] = reg[idx1]
        reg[idx1] &= reg[idx3]
        reg[idx4] ^= reg[idx2]
        reg[idx1] ^= reg[idx0]
        reg[idx0] |= reg[idx3]
        reg[idx0] ^= reg[idx4]
        reg[idx4] ^= reg[idx3]
        reg[idx3] ^= reg[idx2]
        reg[idx2] |= reg[idx1]
        reg[idx2] ^= reg[idx4]
        reg[idx4] ^= MASK_32BIT
        reg[idx4] |= reg[idx1]
        reg[idx1] ^= reg[idx3]
        reg[idx1] ^= reg[idx4]
        reg[idx3] |= reg[idx0]
        reg[idx1] ^= reg[idx3]
        reg[idx4] ^= reg[idx3]

    @staticmethod
    def sub_box1(reg: List[int], idx0: int, idx1: int, idx2: int, idx3: int, idx4: int) -> None:
        """S-блок 1 алгоритма Serpent"""
        reg[idx0] ^= MASK_32BIT
        reg[idx2] ^= MASK_32BIT
        reg[idx4] = reg[idx0]
        reg[idx0] &= reg[idx1]
        reg[idx2] ^= reg[idx0]
        reg[idx0] |= reg[idx3]
        reg[idx3] ^= reg[idx2]
        reg[idx1] ^= reg[idx0]
        reg[idx0] ^= reg[idx4]
        reg[idx4] |= reg[idx1]
        reg[idx1] ^= reg[idx3]
        reg[idx2] |= reg[idx0]
        reg[idx2] &= reg[idx4]
        reg[idx0] ^= reg[idx1]
        reg[idx1] &= reg[idx2]
        reg[idx1] ^= reg[idx0]
        reg[idx0] &= reg[idx2]
        reg[idx0] ^= reg[idx4]

    @staticmethod
    def sub_box2(reg: List[int], idx0: int, idx1: int, idx2: int, idx3: int, idx4: int) -> None:
        """S-блок 2 алгоритма Serpent"""
        reg[idx4] = reg[idx0]
        reg[idx0] &= reg[idx2]
        reg[idx0] ^= reg[idx3]
        reg[idx2] ^= reg[idx1]
        reg[idx2] ^= reg[idx0]
        reg[idx3] |= reg[idx4]
        reg[idx3] ^= reg[idx1]
        reg[idx4] ^= reg[idx2]
        reg[idx1] = reg[idx3]
        reg[idx3] |= reg[idx4]
        reg[idx3] ^= reg[idx0]
        reg[idx0] &= reg[idx1]
        reg[idx4] ^= reg[idx0]
        reg[idx1] ^= reg[idx3]
        reg[idx1] ^= reg[idx4]
        reg[idx4] ^= MASK_32BIT

    @staticmethod
    def sub_box3(reg: List[int], idx0: int, idx1: int, idx2: int, idx3: int, idx4: int) -> None:
        """S-блок 3 алгоритма Serpent"""
        reg[idx4] = reg[idx0]
        reg[idx0] |= reg[idx3]
        reg[idx3] ^= reg[idx1]
        reg[idx1] &= reg[idx4]
        reg[idx4] ^= reg[idx2]
        reg[idx2] ^= reg[idx3]
        reg[idx3] &= reg[idx0]
        reg[idx4] |= reg[idx1]
        reg[idx3] ^= reg[idx4]
        reg[idx0] ^= reg[idx1]
        reg[idx4] &= reg[idx0]
        reg[idx1] ^= reg[idx3]
        reg[idx4] ^= reg[idx2]
        reg[idx1] |= reg[idx0]
        reg[idx1] ^= reg[idx2]
        reg[idx0] ^= reg[idx3]
        reg[idx2] = reg[idx1]
        reg[idx1] |= reg[idx3]
        reg[idx1] ^= reg[idx0]

    @staticmethod
    def sub_box4(reg: List[int], idx0: int, idx1: int, idx2: int, idx3: int, idx4: int) -> None:
        """S-блок 4 алгоритма Serpent"""
        reg[idx1] ^= reg[idx3]
        reg[idx3] ^= MASK_32BIT
        reg[idx2] ^= reg[idx3]
        reg[idx3] ^= reg[idx0]
        reg[idx4] = reg[idx1]
        reg[idx1] &= reg[idx3]
        reg[idx1] ^= reg[idx2]
        reg[idx4] ^= reg[idx3]
        reg[idx0] ^= reg[idx4]
        reg[idx2] &= reg[idx4]
        reg[idx2] ^= reg[idx0]
        reg[idx0] &= reg[idx1]
        reg[idx3] ^= reg[idx0]
        reg[idx4] |= reg[idx1]
        reg[idx4] ^= reg[idx0]
        reg[idx0] |= reg[idx3]
        reg[idx0] ^= reg[idx2]
        reg[idx2] &= reg[idx3]
        reg[idx0] ^= MASK_32BIT
        reg[idx4] ^= reg[idx2]

    @staticmethod
    def sub_box5(reg: List[int], idx0: int, idx1: int, idx2: int, idx3: int, idx4: int) -> None:
        """S-блок 5 алгоритма Serpent"""
        reg[idx0] ^= reg[idx1]
        reg[idx1] ^= reg[idx3]
        reg[idx3] ^= MASK_32BIT
        reg[idx4] = reg[idx1]
        reg[idx1] &= reg[idx0]
        reg[idx2] ^= reg[idx3]
        reg[idx1] ^= reg[idx2]
        reg[idx2] |= reg[idx4]
        reg[idx4] ^= reg[idx3]
        reg[idx3] &= reg[idx1]
        reg[idx3] ^= reg[idx0]
        reg[idx4] ^= reg[idx1]
        reg[idx4] ^= reg[idx2]
        reg[idx2] ^= reg[idx0]
        reg[idx0] &= reg[idx3]
        reg[idx2] ^= MASK_32BIT
        reg[idx0] ^= reg[idx4]
        reg[idx4] |= reg[idx3]
        reg[idx2] ^= reg[idx4]

    @staticmethod
    def sub_box6(reg: List[int], idx0: int, idx1: int, idx2: int, idx3: int, idx4: int) -> None:
        """S-блок 6 алгоритма Serpent"""
        reg[idx2] ^= MASK_32BIT
        reg[idx4] = reg[idx3]
        reg[idx3] &= reg[idx0]
        reg[idx0] ^= reg[idx4]
        reg[idx3] ^= reg[idx2]
        reg[idx2] |= reg[idx4]
        reg[idx1] ^= reg[idx3]
        reg[idx2] ^= reg[idx0]
        reg[idx0] |= reg[idx1]
        reg[idx2] ^= reg[idx1]
        reg[idx4] ^= reg[idx0]
        reg[idx0] |= reg[idx3]
        reg[idx0] ^= reg[idx2]
        reg[idx4] ^= reg[idx3]
        reg[idx4] ^= reg[idx0]
        reg[idx3] ^= MASK_32BIT
        reg[idx2] &= reg[idx4]
        reg[idx2] ^= reg[idx3]

    @staticmethod
    def sub_box7(reg: List[int], idx0: int, idx1: int, idx2: int, idx3: int, idx4: int) -> None:
        """S-блок 7 алгоритма Serpent"""
        reg[idx4] = reg[idx1]
        reg[idx1] |= reg[idx2]
        reg[idx1] ^= reg[idx3]
        reg[idx4] ^= reg[idx2]
        reg[idx2] ^= reg[idx1]
        reg[idx3] |= reg[idx4]
        reg[idx3] &= reg[idx0]
        reg[idx4] ^= reg[idx2]
        reg[idx3] ^= reg[idx1]
        reg[idx1] |= reg[idx4]
        reg[idx1] ^= reg[idx0]
        reg[idx0] |= reg[idx4]
        reg[idx0] ^= reg[idx2]
        reg[idx1] ^= reg[idx4]
        reg[idx2] ^= reg[idx1]
        reg[idx1] &= reg[idx0]
        reg[idx1] ^= reg[idx4]
        reg[idx2] ^= MASK_32BIT
        reg[idx2] |= reg[idx0]
        reg[idx4] ^= reg[idx2]

    @staticmethod
    def word_update(word_list: List[int], index: int, idx5: int, idx3: int, idx1: int, const_counter: int) -> None:
        """
        Обновление одного слова в процессе генерации ключей

        Исходные параметры:
            word_list: список из 8 слов
            index: индекс обновляемого слова
            idx5, idx3, idx1: индексы слов для XOR
            const_counter: константа для добавления
        """
        word_list[index] = rotate_left(
            word_list[index] ^ word_list[idx5] ^ word_list[idx3] ^ word_list[idx1] ^
            (0x9E3779B9 ^ const_counter), 11
        )

    @staticmethod
    def word_update_group0(word_list: List[int], const_counter: int) -> None:
        """Обновление слов 0-3"""
        CustomSosemanuk.word_update(word_list, 0, 3, 5, 7, const_counter)
        CustomSosemanuk.word_update(word_list, 1, 4, 6, 0, const_counter + 1)
        CustomSosemanuk.word_update(word_list, 2, 5, 7, 1, const_counter + 2)
        CustomSosemanuk.word_update(word_list, 3, 6, 0, 2, const_counter + 3)

    @staticmethod
    def word_update_group1(word_list: List[int], const_counter: int) -> None:
        """Обновление слов 4-7"""
        CustomSosemanuk.word_update(word_list, 4, 7, 1, 3, const_counter)
        CustomSosemanuk.word_update(word_list, 5, 0, 2, 4, const_counter + 1)
        CustomSosemanuk.word_update(word_list, 6, 1, 3, 5, const_counter + 2)
        CustomSosemanuk.word_update(word_list, 7, 2, 4, 6, const_counter + 3)

    @staticmethod
    def subkey_schedule(sub_func, word_list: List[int], idx0: int, idx1: int, idx2: int,
                        idx3: int, out_idx0: int, out_idx1: int, out_idx2: int,
                        out_idx3: int, sub_keys: List[int], offset: int) -> None:
        """Общая функция для расписания подключей"""
        temp_reg = [word_list[idx0], word_list[idx1], word_list[idx2], word_list[idx3], 0]
        sub_func(temp_reg, 0, 1, 2, 3, 4)
        sub_keys[offset] = temp_reg[out_idx0]
        sub_keys[offset + 1] = temp_reg[out_idx1]
        sub_keys[offset + 2] = temp_reg[out_idx2]
        sub_keys[offset + 3] = temp_reg[out_idx3]

    @staticmethod
    def subkey_schedule0(word_list: List[int], sub_keys: List[int], offset: int) -> None:
        """Расписание подключей для S-блока 0"""
        CustomSosemanuk.subkey_schedule(
            CustomSosemanuk.sub_box0, word_list, 4, 5, 6, 7,
            1, 4, 2, 0, sub_keys, offset
        )

    @staticmethod
    def subkey_schedule1(word_list: List[int], sub_keys: List[int], offset: int) -> None:
        """Расписание подключей для S-блока 1"""
        CustomSosemanuk.subkey_schedule(
            CustomSosemanuk.sub_box1, word_list, 0, 1, 2, 3,
            2, 0, 3, 1, sub_keys, offset
        )

    @staticmethod
    def subkey_schedule2(word_list: List[int], sub_keys: List[int], offset: int) -> None:
        """Расписание подключей для S-блока 2"""
        CustomSosemanuk.subkey_schedule(
            CustomSosemanuk.sub_box2, word_list, 4, 5, 6, 7,
            2, 3, 1, 4, sub_keys, offset
        )

    @staticmethod
    def subkey_schedule3(word_list: List[int], sub_keys: List[int], offset: int) -> None:
        """Расписание подключей для S-блока 3"""
        CustomSosemanuk.subkey_schedule(
            CustomSosemanuk.sub_box3, word_list, 0, 1, 2, 3,
            1, 2, 3, 4, sub_keys, offset
        )

    @staticmethod
    def subkey_schedule4(word_list: List[int], sub_keys: List[int], offset: int) -> None:
        """Расписание подключей для S-блока 4"""
        CustomSosemanuk.subkey_schedule(
            CustomSosemanuk.sub_box4, word_list, 4, 5, 6, 7,
            1, 4, 0, 3, sub_keys, offset
        )

    @staticmethod
    def subkey_schedule5(word_list: List[int], sub_keys: List[int], offset: int) -> None:
        """Расписание подключей для S-блока 5"""
        CustomSosemanuk.subkey_schedule(
            CustomSosemanuk.sub_box5, word_list, 0, 1, 2, 3,
            1, 3, 0, 2, sub_keys, offset
        )

    @staticmethod
    def subkey_schedule6(word_list: List[int], sub_keys: List[int], offset: int) -> None:
        """Расписание подключей для S-блока 6"""
        CustomSosemanuk.subkey_schedule(
            CustomSosemanuk.sub_box6, word_list, 4, 5, 6, 7,
            0, 1, 4, 2, sub_keys, offset
        )

    @staticmethod
    def subkey_schedule7(word_list: List[int], sub_keys: List[int], offset: int) -> None:
        """Расписание подключей для S-блока 7"""
        CustomSosemanuk.subkey_schedule(
            CustomSosemanuk.sub_box7, word_list, 0, 1, 2, 3,
            4, 3, 1, 0, sub_keys, offset
        )

    @staticmethod
    def serpent_linear_transform(x_reg: List[int], idx0: int, idx1: int, idx2: int, idx3: int) -> None:
        """
        Линейное преобразование Serpent

        Исходные параметры:
            x_reg: список из 5 регистров
            idx0, idx1, idx2, idx3: индексы регистров для преобразования
        """
        x_reg[idx0] = rotate_left(x_reg[idx0], 13)
        x_reg[idx2] = rotate_left(x_reg[idx2], 3)
        x_reg[idx1] = x_reg[idx1] ^ x_reg[idx0] ^ x_reg[idx2]
        x_reg[idx3] = x_reg[idx3] ^ x_reg[idx2] ^ ((x_reg[idx0] << 3) & MASK_32BIT)
        x_reg[idx1] = rotate_left(x_reg[idx1], 1)
        x_reg[idx3] = rotate_left(x_reg[idx3], 7)
        x_reg[idx0] = x_reg[idx0] ^ x_reg[idx1] ^ x_reg[idx3]
        x_reg[idx2] = x_reg[idx2] ^ x_reg[idx3] ^ ((x_reg[idx1] << 7) & MASK_32BIT)
        x_reg[idx0] = rotate_left(x_reg[idx0], 5)
        x_reg[idx2] = rotate_left(x_reg[idx2], 22)

    @staticmethod
    def apply_key(sub_keys: List[int], offset: int, x_reg: List[int],
                  idx0: int, idx1: int, idx2: int, idx3: int) -> None:
        """Применение подключей к регистрам"""
        x_reg[idx0] ^= sub_keys[offset]
        x_reg[idx1] ^= sub_keys[offset + 1]
        x_reg[idx2] ^= sub_keys[offset + 2]
        x_reg[idx3] ^= sub_keys[offset + 3]

    @staticmethod
    def full_serpent_step(sub_func, sub_keys: List[int], offset: int,
                          reg: List[int], idx0: int, idx1: int, idx2: int,
                          idx3: int, idx4: int, out_idx0: int, out_idx1: int,
                          out_idx2: int, out_idx3: int) -> None:
        """Полный шаг Serpent за исключением последнего"""
        CustomSosemanuk.apply_key(sub_keys, offset, reg, idx0, idx1, idx2, idx3)
        sub_func(reg, idx0, idx1, idx2, idx3, idx4)
        CustomSosemanuk.serpent_linear_transform(reg, out_idx0, out_idx1, out_idx2, out_idx3)

    @staticmethod
    def full_serpent_final(sub_func, sub_keys: List[int], offset: int,
                           reg: List[int], idx0: int, idx1: int, idx2: int,
                           idx3: int, idx4: int, out_idx0: int, out_idx1: int,
                           out_idx2: int, out_idx3: int) -> None:
        """Финальный шаг Serpent с дополнительным применением ключа"""
        CustomSosemanuk.apply_key(sub_keys, offset, reg, idx0, idx1, idx2, idx3)
        sub_func(reg, idx0, idx1, idx2, idx3, idx4)
        CustomSosemanuk.serpent_linear_transform(reg, out_idx0, out_idx1, out_idx2, out_idx3)
        CustomSosemanuk.apply_key(sub_keys, offset + 4, reg, out_idx0, out_idx1, out_idx2, out_idx3)

    def __init__(self, key: bytes, iv: Optional[bytes] = None):
        """
        Инициализация шифра с ключом и вектором инициализации

        Исходные параметры:
            key: ключ (1-32 байта)
            iv: вектор инициализации (до 16 байт, опционально)
        Ошибка:
            ValueError: при неверной длине ключа
        """
        if not (MIN_KEY_LEN <= len(key) <= MAX_KEY_LEN):
            raise ValueError(f'Ключ должен быть длиной от {MIN_KEY_LEN} до {MAX_KEY_LEN} байт')

        # Подготовка ключа
        key_bytes = key
        if len(key_bytes) < MAX_KEY_LEN:
            # Дополнение ключа, если он короче максимальной длины
            key_bytes += b'\1' + ((MAX_KEY_LEN - 1) - len(key_bytes)) * b'\0'

        # Преобразование ключа в 8 32-битных слова
        word_list = list(struct.unpack('<8L', key_bytes))

        # Инициализация массива подключей
        sub_keys = [0] * 100

        # Генерация подключей для Serpent24, 24 раунда
        # Процедура инициализации Sosemanuk
        CustomSosemanuk.word_update_group0(word_list, 0)
        CustomSosemanuk.subkey_schedule3(word_list, sub_keys, 0)
        CustomSosemanuk.word_update_group1(word_list, 4)
        CustomSosemanuk.subkey_schedule2(word_list, sub_keys, 4)
        CustomSosemanuk.word_update_group0(word_list, 8)
        CustomSosemanuk.subkey_schedule1(word_list, sub_keys, 8)
        CustomSosemanuk.word_update_group1(word_list, 12)
        CustomSosemanuk.subkey_schedule0(word_list, sub_keys, 12)
        CustomSosemanuk.word_update_group0(word_list, 16)
        CustomSosemanuk.subkey_schedule7(word_list, sub_keys, 16)
        CustomSosemanuk.word_update_group1(word_list, 20)
        CustomSosemanuk.subkey_schedule6(word_list, sub_keys, 20)
        CustomSosemanuk.word_update_group0(word_list, 24)
        CustomSosemanuk.subkey_schedule5(word_list, sub_keys, 24)
        CustomSosemanuk.word_update_group1(word_list, 28)
        CustomSosemanuk.subkey_schedule4(word_list, sub_keys, 28)
        CustomSosemanuk.word_update_group0(word_list, 32)
        CustomSosemanuk.subkey_schedule3(word_list, sub_keys, 32)
        CustomSosemanuk.word_update_group1(word_list, 36)
        CustomSosemanuk.subkey_schedule2(word_list, sub_keys, 36)
        CustomSosemanuk.word_update_group0(word_list, 40)
        CustomSosemanuk.subkey_schedule1(word_list, sub_keys, 40)
        CustomSosemanuk.word_update_group1(word_list, 44)
        CustomSosemanuk.subkey_schedule0(word_list, sub_keys, 44)
        CustomSosemanuk.word_update_group0(word_list, 48)
        CustomSosemanuk.subkey_schedule7(word_list, sub_keys, 48)
        CustomSosemanuk.word_update_group1(word_list, 52)
        CustomSosemanuk.subkey_schedule6(word_list, sub_keys, 52)
        CustomSosemanuk.word_update_group0(word_list, 56)
        CustomSosemanuk.subkey_schedule5(word_list, sub_keys, 56)
        CustomSosemanuk.word_update_group1(word_list, 60)
        CustomSosemanuk.subkey_schedule4(word_list, sub_keys, 60)
        CustomSosemanuk.word_update_group0(word_list, 64)
        CustomSosemanuk.subkey_schedule3(word_list, sub_keys, 64)
        CustomSosemanuk.word_update_group1(word_list, 68)
        CustomSosemanuk.subkey_schedule2(word_list, sub_keys, 68)
        CustomSosemanuk.word_update_group0(word_list, 72)
        CustomSosemanuk.subkey_schedule1(word_list, sub_keys, 72)
        CustomSosemanuk.word_update_group1(word_list, 76)
        CustomSosemanuk.subkey_schedule0(word_list, sub_keys, 76)
        CustomSosemanuk.word_update_group0(word_list, 80)
        CustomSosemanuk.subkey_schedule7(word_list, sub_keys, 80)
        CustomSosemanuk.word_update_group1(word_list, 84)
        CustomSosemanuk.subkey_schedule6(word_list, sub_keys, 84)
        CustomSosemanuk.word_update_group0(word_list, 88)
        CustomSosemanuk.subkey_schedule5(word_list, sub_keys, 88)
        CustomSosemanuk.word_update_group1(word_list, 92)
        CustomSosemanuk.subkey_schedule4(word_list, sub_keys, 92)
        CustomSosemanuk.word_update_group0(word_list, 96)
        CustomSosemanuk.subkey_schedule3(word_list, sub_keys, 96)

        # Подготовка IV
        if iv is None:
            iv_bytes = b'\0' * MAX_IV_LEN
        else:
            iv_bytes = iv[:MAX_IV_LEN]
            if len(iv_bytes) < MAX_IV_LEN:
                # Дополнение IV нулями в случае необходимости
                iv_bytes += b'\0' * (MAX_IV_LEN - len(iv_bytes))

        # Преобразование IV в 4 32-битных слова
        temp_reg = list(struct.unpack('<4L', iv_bytes))
        temp_reg.append(0)  # 5-й элемент для временных вычислений

        # Инициализация регистра сдвига
        shift_reg = [0] * 10

        # Шифрование IV с использованием Serpent24
        # Инициализации состояния шифра
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box0, sub_keys, 0, temp_reg, 0, 1, 2, 3, 4, 1, 4, 2, 0)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box1, sub_keys, 4, temp_reg, 1, 4, 2, 0, 3, 2, 1, 0, 4)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box2, sub_keys, 8, temp_reg, 2, 1, 0, 4, 3, 0, 4, 1, 3)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box3, sub_keys, 12, temp_reg, 0, 4, 1, 3, 2, 4, 1, 3, 2)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box4, sub_keys, 16, temp_reg, 4, 1, 3, 2, 0, 1, 0, 4, 2)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box5, sub_keys, 20, temp_reg, 1, 0, 4, 2, 3, 0, 2, 1, 4)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box6, sub_keys, 24, temp_reg, 0, 2, 1, 4, 3, 0, 2, 3, 1)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box7, sub_keys, 28, temp_reg, 0, 2, 3, 1, 4, 4, 1, 2, 0)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box0, sub_keys, 32, temp_reg, 4, 1, 2, 0, 3, 1, 3, 2, 4)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box1, sub_keys, 36, temp_reg, 1, 3, 2, 4, 0, 2, 1, 4, 3)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box2, sub_keys, 40, temp_reg, 2, 1, 4, 3, 0, 4, 3, 1, 0)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box3, sub_keys, 44, temp_reg, 4, 3, 1, 0, 2, 3, 1, 0, 2)

        shift_reg[9] = temp_reg[3]
        shift_reg[8] = temp_reg[1]
        shift_reg[7] = temp_reg[0]
        shift_reg[6] = temp_reg[2]

        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box4, sub_keys, 48, temp_reg, 3, 1, 0, 2, 4, 1, 4, 3, 2)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box5, sub_keys, 52, temp_reg, 1, 4, 3, 2, 0, 4, 2, 1, 3)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box6, sub_keys, 56, temp_reg, 4, 2, 1, 3, 0, 4, 2, 0, 1)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box7, sub_keys, 60, temp_reg, 4, 2, 0, 1, 3, 3, 1, 2, 4)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box0, sub_keys, 64, temp_reg, 3, 1, 2, 4, 0, 1, 0, 2, 3)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box1, sub_keys, 68, temp_reg, 1, 0, 2, 3, 4, 2, 1, 3, 0)

        fsm_reg1 = temp_reg[2]  # R1
        shift_reg[4] = temp_reg[1]
        fsm_reg2 = temp_reg[3]  # R2
        shift_reg[5] = temp_reg[0]

        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box2, sub_keys, 72, temp_reg, 2, 1, 3, 0, 4, 3, 0, 1, 4)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box3, sub_keys, 76, temp_reg, 3, 0, 1, 4, 2, 0, 1, 4, 2)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box4, sub_keys, 80, temp_reg, 0, 1, 4, 2, 3, 1, 3, 0, 2)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box5, sub_keys, 84, temp_reg, 1, 3, 0, 2, 4, 3, 2, 1, 0)
        CustomSosemanuk.full_serpent_step(CustomSosemanuk.sub_box6, sub_keys, 88, temp_reg, 3, 2, 1, 0, 4, 3, 2, 4, 1)
        CustomSosemanuk.full_serpent_final(CustomSosemanuk.sub_box7, sub_keys, 92, temp_reg, 3, 2, 4, 1, 0, 0, 1, 2, 3)

        shift_reg[3] = temp_reg[0]
        shift_reg[2] = temp_reg[1]
        shift_reg[1] = temp_reg[2]
        shift_reg[0] = temp_reg[3]

        # Сохранение состояние
        self.shift_reg = shift_reg  # LFSR регистр, 10 слов
        self.fsm_reg = [fsm_reg1, fsm_reg2]  # FSM регистры, 2 слова
        self.keystream_buf = None  # Буфер гаммы
        self.buf_position = 0  # Позиция в буфере

    @staticmethod
    def internal_step(shift_reg: List[int], idx0: int, idx1: int, idx2: int,
                      idx3: int, idx4: int, idx5: int, idx6: int, idx7: int,
                      idx8: int, idx9: int, fsm_reg: List[int]) -> Tuple[int, int]:
        """
        Соло внутренний шаг генерации гаммы

        Исходные параметры:
            shift_reg: регистр сдвига, 10 элементов
            idx0-idx9: индексы для доступа к shift_reg
            fsm_reg: регистры конечного автомата, 2 элемента
        Результат на выходе:
            Кортеж (v, u) - значения для дальнейшей обработки
        """
        # Обновление FSM (Finite State Machine)
        temp_tt = special_mux(fsm_reg[0], shift_reg[idx1], shift_reg[idx8])
        old_r0 = fsm_reg[0]
        fsm_reg[0] = (fsm_reg[1] + temp_tt) & MASK_32BIT
        temp_tt = (old_r0 * 0x54655307) & MASK_32BIT
        fsm_reg[1] = rotate_left(temp_tt, 7)

        # Обновление LFSR (Linear Feedback Shift Register)
        temp_dd = shift_reg[idx0]
        shift_reg[idx0] = multiply_alpha(shift_reg[idx0]) ^ multiply_inv_alpha(shift_reg[idx3]) ^ shift_reg[idx9]

        # Комбинация LFSR и FSM для получения выходного значения
        temp_ee = ((shift_reg[idx9] + fsm_reg[0]) & MASK_32BIT) ^ fsm_reg[1]

        return temp_dd, temp_ee

    @staticmethod
    def serpent_round_apply(u0: int, u1: int, u2: int, u3: int,
                            v0: int, v1: int, v2: int, v3: int) -> bytes:
        """
        Применение одного раунда Serpent к сгенерированным значениям.

        Исходные параметры:
            u0-u3: входные значения от FSM
            v0-v3: входные значения от LFSR
        Результат на выходе:
            16 байт гаммы
        """
        temp_u = [u0, u1, u2, u3, 0]
        CustomSosemanuk.sub_box2(temp_u, 0, 1, 2, 3, 4)
        return struct.pack('<4L', temp_u[2] ^ v0, temp_u[3] ^ v1, temp_u[1] ^ v2, temp_u[4] ^ v3)

    def generate_keystream_block(self) -> None:
        """Генерация следующего блока гаммы"""
        shift_reg = self.shift_reg
        fsm_reg = self.fsm_reg

        keystream = b''

        # 5 итераций по 4 шага
        # Итерация 1
        v0, u0 = CustomSosemanuk.internal_step(shift_reg, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, fsm_reg)
        v1, u1 = CustomSosemanuk.internal_step(shift_reg, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, fsm_reg)
        v2, u2 = CustomSosemanuk.internal_step(shift_reg, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, fsm_reg)
        v3, u3 = CustomSosemanuk.internal_step(shift_reg, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, fsm_reg)
        keystream += CustomSosemanuk.serpent_round_apply(u0, u1, u2, u3, v0, v1, v2, v3)

        # Итерация 2
        v0, u0 = CustomSosemanuk.internal_step(shift_reg, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, fsm_reg)
        v1, u1 = CustomSosemanuk.internal_step(shift_reg, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, fsm_reg)
        v2, u2 = CustomSosemanuk.internal_step(shift_reg, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, fsm_reg)
        v3, u3 = CustomSosemanuk.internal_step(shift_reg, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, fsm_reg)
        keystream += CustomSosemanuk.serpent_round_apply(u0, u1, u2, u3, v0, v1, v2, v3)

        # Итерация 3
        v0, u0 = CustomSosemanuk.internal_step(shift_reg, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, fsm_reg)
        v1, u1 = CustomSosemanuk.internal_step(shift_reg, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, fsm_reg)
        v2, u2 = CustomSosemanuk.internal_step(shift_reg, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, fsm_reg)
        v3, u3 = CustomSosemanuk.internal_step(shift_reg, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, fsm_reg)
        keystream += CustomSosemanuk.serpent_round_apply(u0, u1, u2, u3, v0, v1, v2, v3)

        # Итерация 4
        v0, u0 = CustomSosemanuk.internal_step(shift_reg, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, fsm_reg)
        v1, u1 = CustomSosemanuk.internal_step(shift_reg, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, fsm_reg)
        v2, u2 = CustomSosemanuk.internal_step(shift_reg, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, fsm_reg)
        v3, u3 = CustomSosemanuk.internal_step(shift_reg, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, fsm_reg)
        keystream += CustomSosemanuk.serpent_round_apply(u0, u1, u2, u3, v0, v1, v2, v3)

        # Итерация 5
        v0, u0 = CustomSosemanuk.internal_step(shift_reg, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, fsm_reg)
        v1, u1 = CustomSosemanuk.internal_step(shift_reg, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, fsm_reg)
        v2, u2 = CustomSosemanuk.internal_step(shift_reg, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, fsm_reg)
        v3, u3 = CustomSosemanuk.internal_step(shift_reg, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, fsm_reg)
        keystream += CustomSosemanuk.serpent_round_apply(u0, u1, u2, u3, v0, v1, v2, v3)

        # Сохраняем состояние
        self.shift_reg = shift_reg
        self.fsm_reg = fsm_reg
        self.keystream_buf = keystream

    @staticmethod
    def xor_data_block(data_block: bytes, keystream: bytes, keystream_pos: int = 0) -> bytes:
        """
        XOR данных с гаммой.

        Исходные параметры:
            data_block: блок данных для шифрования
            keystream: буфер гаммы
            keystream_pos: позиция в буфере гаммы
        Результат на выходе:
            Зашифрованный/расшифрованный блок
        """
        result = bytearray(data_block)
        for i in range(len(result)):
            result[i] ^= keystream[i + keystream_pos]
        return bytes(result)

    def encrypt_data(self, input_data: bytes) -> bytes:
        """
        Шифрование данных.

        Исходный параметр:
            input_data: исходные данные для шифрования
        Результат на выходе:
            Зашифрованные данные
        """
        output = b''
        current_pos = self.buf_position
        data_pos = 0

        # Обработка остатка из предыдущего блока
        if current_pos != 0:
            remain_len = min(KESTREAM_BLOCK - current_pos, len(input_data))
            output += CustomSosemanuk.xor_data_block(
                input_data[:remain_len],
                self.keystream_buf,
                current_pos
            )
            current_pos += remain_len
            if current_pos == KESTREAM_BLOCK:
                current_pos = 0
            data_pos = remain_len

        # Обработка полных блоков
        if data_pos < len(input_data):
            for block_start in range(data_pos, len(input_data), KESTREAM_BLOCK):
                block_end = min(block_start + KESTREAM_BLOCK, len(input_data))
                block = input_data[block_start:block_end]

                # Генерация новой гаммы, в случае необходимости
                if block_start == data_pos or len(block) == KESTREAM_BLOCK:
                    self.generate_keystream_block()

                output += CustomSosemanuk.xor_data_block(block, self.keystream_buf)

            # Обновление позиции в буфере
            current_pos = (len(input_data) - data_pos) % KESTREAM_BLOCK

        self.buf_position = current_pos
        return output

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        Расшифрование данных (симметрично шифрованию).

        Исходный параметр:
            encrypted_data: зашифрованные данные
        Результат на выходе:
            Расшифрованные данные
        """
        return self.encrypt_data(encrypted_data)