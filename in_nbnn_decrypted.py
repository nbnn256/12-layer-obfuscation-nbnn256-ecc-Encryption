#!/usr/bin/env python3.12
"""
🔐 封板 v3.4-final：12层字节混淆 + Argon2id + 注册表6值(5硬件+240bit Rand) + 旧char兼容
基准：用户贴的 v3.2 全文
修① import sys
修② argon2 三入口兜底（23.x/25.x/conda 都扛）
修③ build_output 补 层序/参数/子种（v3.2 漏写 → meta[idx]==[] → 三阶段全挂"层序不对"）
修④ parse_integrated 补三读
修⑤ OLD_DEC: _old_dec_oct %8→%3 / _old_dec_htmlh 缺左括号
修⑥ encrypt_mode 收 try/except（前几轮腰斩点）
"""
import random, hashlib, base64, binascii, socket, uuid, ipaddress, lzma
import datetime, os, argparse, secrets, ctypes, winreg, re, traceback, json, subprocess, tempfile
from ctypes import wintypes
import sys   ### 修①
sys.set_int_max_str_digits(0)

# ==================== 实时金价获取 ====================
def fetch_gold_price():
    import urllib.request
    urls = [
        ("http://api.gold-api.com/price/XAU", lambda d: int(d.get("price", 2035))),
        ("https://forex-data-feed.swissquote.com/public-quotes/bboquotes/instrument/XAU/USD", lambda d: int(d[0]["spreadProfilePrices"][0]["bid"]) if isinstance(d, list) and d else 2035),
    ]
    for url, extract in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                return extract(data)
        except:
            continue
    return 2035

def fetch_max_temp():
    import urllib.request
    try:
        url = f"https://api.open-meteo.com/v1/forecast?latitude={DEFAULT_LAT}&longitude={DEFAULT_LON}&daily=temperature_2m_max&timezone=auto&forecast_days=1"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
            return int(data["daily"]["temperature_2m_max"][0])
    except:
        pass
    return 61

# ==================== 全局配置 ====================
LAYER_COUNT = 12
REG_PATH = r"Software\JMEncrypt"
REG_FLAG = "INIT_FLAG"
REG_RAND = "MasterRand"
REG_DEV_KEY = "DeviceKey"
REG_STORE = "SecureStore"
REG_HK_PAIR = "HkPair"
REG_HK_R1 = "HkR1"
REG_PWD_BOX = "PwdBox"
REG_NBNN_B = "NbnnB"
REG_EC_KEY = "EcKey"
REG_8192_R2 = "Tpm8192R2"
REG_8192_R1R2 = "Tpm8192R1R2"
ARGON_TIME_COST = 2
ARGON_MEM_COST = 32768
ARGON_PARALLELISM = 2
HASH_LEN = 16
DEFAULT_LAT, DEFAULT_LON = 39.9042, 116.4074
SEED_DEP_LAYERS = {2, 8, 10}

# ---------- Argon2 三入口兜底  ### 修② ----------
HAS_ARGON2 = False
_hash_secret_raw, _Type = None, None

try:  # 入口① argon2-cffi ≥21 主流
    from argon2.low_level import hash_secret_raw as _hsr, Type as _T
    _hash_secret_raw, _Type = _hsr, _T
    HAS_ARGON2 = True
except Exception:
    pass

if not HAS_ARGON2:
    try:  # 入口② conda 源 / 老命名 argon2_cffi
        from argon2_cffi.low_level import hash_secret_raw as _hsr, Type as _T
        _hash_secret_raw, _Type = _hsr, _T
        HAS_ARGON2 = True
    except Exception:
        pass

if not HAS_ARGON2:
    print("⚠️ argon2-cffi 导入失败，降级PBKDF2（建议 pip install 'argon2-cffi>=23'）")


# ==================== 12层字节混淆（v3.2 基准原样，不动） ====================
def layer_xor(d,p,s): return bytes(b^p for b in d)
def inv_layer_xor(d,p,s): return layer_xor(d,p,s)
def layer_rol(d,p,s):
    p%=8; return d if p==0 else bytes(((b<<p)&0xFF)|(b>>(8-p)) for b in d)
def inv_layer_rol(d,p,s):
    p%=8; return d if p==0 else bytes(((b>>p)|(b<<(8-p)))&0xFF for b in d)
def layer_block_shuffle(d,p,s):
    if len(d)<p or p<=1: return d
    r=random.Random(s); blks=[d[i:i+p] for i in range(0,len(d),p)]; r.shuffle(blks); return b''.join(blks)
def inv_layer_block_shuffle(d,p,s):
    if len(d)<p or p<=1: return d
    r=random.Random(s); n=(len(d)+p-1)//p
    sizes=[min(p,len(d)-i*p) for i in range(n)]
    perm=list(range(n)); r.shuffle(perm)
    res=bytearray(len(d)); pos=0
    for i in range(n):
        sz=sizes[perm[i]]; blk=d[pos:pos+sz]; pos+=sz
        res[perm[i]*p:perm[i]*p+sz]=blk
    return bytes(res)
def layer_reverse(d,p,s): return d[::-1]
def inv_layer_reverse(d,p,s): return layer_reverse(d,p,s)
def layer_swap_nibbles(d,p,s): return bytes(((b&0x0F)<<4)|((b&0xF0)>>4) for b in d)
def inv_layer_swap_nibbles(d,p,s): return layer_swap_nibbles(d,p,s)
def layer_interval_xor(d,p,s):
    if p<=0: return d
    res=bytearray(d)
    for i in range(p-1,len(res),p): res[i]^=p
    return bytes(res)
def inv_layer_interval_xor(d,p,s): return layer_interval_xor(d,p,s)
def layer_block_reverse(d,p,s):
    if len(d)<p or p<=1: return d
    return b''.join(d[i:i+p][::-1] for i in range(0,len(d),p))
def inv_layer_block_reverse(d,p,s): return layer_block_reverse(d,p,s)
def layer_index_xor(d,p,s): return bytes(b^(i%256) for i,b in enumerate(d))
def inv_layer_index_xor(d,p,s): return layer_index_xor(d,p,s)
def layer_group_permute(d,p,s):
    gs=8
    if len(d)<gs: return d
    r=random.Random(s); perm=list(range(gs)); r.shuffle(perm)
    res=bytearray()
    for i in range(0,len(d),gs):
        g=d[i:i+gs]; res.extend(g if len(g)<gs else bytes(g[i] for i in perm))
    return bytes(res)
def inv_layer_group_permute(d,p,s):
    gs=8
    if len(d)<gs: return d
    r=random.Random(s); perm=list(range(gs)); r.shuffle(perm); inv_p=[0]*gs
    for i,p_ in enumerate(perm): inv_p[p_]=i
    res=bytearray()
    for i in range(0,len(d),gs):
        g=d[i:i+gs]; res.extend(g if len(g)<gs else bytes(g[i] for i in inv_p))
    return bytes(res)
def layer_arithmetic_shr(d,p,s):
    p%=8
    if p==0: return d
    return bytes(((b>>p)|(b<<(8-p)))&0xFF for b in d)
def inv_layer_arithmetic_shr(d,p,s):
    p%=8
    if p==0: return d
    return bytes(((b<<p)&0xFF)|((b>>(8-p))&((1<<p)-1)) for b in d)
def layer_prng_xor(d,p,s):
    r=random.Random(s); prng=[r.randint(0,255) for _ in range(len(d))]
    return bytes(b^pr for b,pr in zip(d,prng))
def inv_layer_prng_xor(d,p,s): return layer_prng_xor(d,p,s)
def layer_b64(d,p,s): return base64.b64encode(d)
def inv_layer_b64(d,p,s): return base64.b64decode(d)
BYTE_LAYERS = [
    (layer_xor, inv_layer_xor, "xor"),
    (layer_rol, inv_layer_rol, "rol"),
    (layer_block_shuffle, inv_layer_block_shuffle, "block_shuffle"),
    (layer_reverse, inv_layer_reverse, "reverse"),
    (layer_swap_nibbles, inv_layer_swap_nibbles, "swap_nibbles"),
    (layer_interval_xor, inv_layer_interval_xor, "interval_xor"),
    (layer_block_reverse, inv_layer_block_reverse, "block_reverse"),
    (layer_index_xor, inv_layer_index_xor, "index_xor"),
    (layer_group_permute, inv_layer_group_permute, "group_permute"),
    (layer_arithmetic_shr, inv_layer_arithmetic_shr, "arithmetic_shr"),
    (layer_prng_xor, inv_layer_prng_xor, "prng_xor"),
    (layer_b64, inv_layer_b64, "b64"),
]

# ==================== 旧版12层字符解码器（修⑤笔误） ====================
def _old_dec_hex(d): return binascii.unhexlify(d)
def _old_dec_bin(d):
    s=d.decode(); s=''.join(c for c in s if c in '01')
    if len(s)%8: s=s[:-(len(s)%8)]
    return bytes(int(s[i:i+8],2) for i in range(0,len(s),8))
def _old_dec_dec(d):
    s=d.decode(); s=''.join(c for c in s if c.isdigit())
    if len(s)%3: s=s[:-(len(s)%3)]
    return bytes(int(s[i:i+3]) for i in range(0,len(s),3))
def _old_dec_oct(d):
    s=d.decode(); s=''.join(c for c in s if c in '01234567')
    if len(s)%3: s=s[:-(len(s)%3)]   ### 修⑤a：v3.2 这里写成 %8，改 %3
    return bytes(int(s[i:i+3],8) for i in range(0,len(s),8) if i+3<=len(s))
def _old_dec_uesc(d): return d.decode().encode("unicode_escape")
def _old_dec_ucode(d):
    import re as _re
    s=d.decode(); pts=_re.findall(r'U\+([0-9A-Fa-f]{1,6})',s)
    return ''.join(chr(min(int(h,16),0x10FFFF)) for h in pts).encode()
def _old_dec_htmld(d):
    import re as _re
    s=d.decode(); pts=_re.findall(r'&#(\d+);',s)
    return ''.join(chr(min(int(x),0x10FFFF)) for x in pts if x.isdigit()).encode()
def _old_dec_htmlh(d):
    import re as _re
    s=d.decode(); pts=_re.findall(r'&#x([0-9A-Fa-f]+);',s)
    return ''.join(chr(min(int(x),16),0x10FFFF) for x in pts).encode()  ### 修⑤b：补左括号
def _old_dec_b64(d): return base64.b64decode(d)
def _old_dec_utf8h(d): return binascii.unhexlify(d)
def _old_dec_puny(d): return d.decode().encode("punycode")
def _old_enc_rot(d,sft):
    out=[]
    for c in d.decode():
        if 'a'<=c<='z': out.append(chr((ord(c)-97+sft)%26+97))
        elif 'A'<=c<='Z': out.append(chr((ord(c)-65+sft)%26+65))
        else: out.append(c)
    return ''.join(out).encode()
def _old_dec_rot(d,sft): return _old_enc_rot(d, 26-sft)
OLD_DEC_MAP = [_old_dec_hex, _old_dec_bin, _old_dec_dec, _old_dec_oct,
               _old_dec_uesc, _old_dec_ucode, _old_dec_htmld, _old_dec_htmlh,
               _old_dec_b64, _old_dec_utf8h, _old_dec_puny]

# ==================== 硬件信息（v3.2 基准原样） ====================
def get_cpu_model():
    try:
        k=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
        v=winreg.QueryValueEx(k,"ProcessorNameString")[0]; winreg.CloseKey(k); return v.strip()[:50]
    except: return "unknown_cpu"
def get_cpu_sn():
    try:
        k=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
        v=winreg.QueryValueEx(k,"ProcessorId")[0]; winreg.CloseKey(k); return v
    except: return "UNKNOWN"
def get_bios_sn():
    try:
        k=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r"HARDWARE\DESCRIPTION\System\BIOS")
        v=winreg.QueryValueEx(k,"SerialNumber")[0]; winreg.CloseKey(k)
        return v if v!="To be filled by O.E.M." else "UNKNOWN_BIOS"
    except: return "UNKNOWN_BIOS"
def get_ip():
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(("8.8.8.8",80))
        ipv4=s.getsockname()[0]; s.close()
        return int(ipaddress.IPv4Address(ipv4))
    except:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if not ip.startswith("127.") and ip.count('.') == 3:
                return int(ipaddress.IPv4Address(ip))
    except:
        pass
    return 192168001

def get_disk_serial():
    try:
        vs = ctypes.c_uint32()
        if ctypes.windll.kernel32.GetVolumeInformationA(b"C:\\", None, 0, ctypes.byref(vs), None, None, None, 0):
            return format(vs.value, '08X')
    except:
        pass
    return "UNKNOWN_DISK"

# ==================== 注册表6值（v3.2 基准原样） ====================
def _gen_master_rand(vol, ts, bios, sid, cpu):
    raw = secrets.randbits(240)
    bind = f"{vol}|{ts}|{bios}|{sid}|{cpu}".encode()
    h = hashlib.sha256(bind + ts.to_bytes(8,'big')).digest()
    h_exp = hashlib.shake_256(h).digest(30)
    mixed = int.from_bytes(h_exp,'big') ^ raw
    return hex(mixed)[2:].zfill(60)

DEVICE_KEY_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

# ---------- DPAPI (CryptProtectData) ----------
class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

def dpapi_protect(data):
    blob = _DATA_BLOB(len(data), ctypes.cast(data, ctypes.POINTER(ctypes.c_byte)))
    out = _DATA_BLOB()
    if ctypes.windll.crypt32.CryptProtectData(ctypes.byref(blob), None, None, None, None, 0, ctypes.byref(out)):
        result = ctypes.string_at(out.pbData, out.cbData)
        ctypes.windll.kernel32.LocalFree(out.pbData)
        return result
    raise ctypes.WinError()

def dpapi_unprotect(data):
    blob = _DATA_BLOB(len(data), ctypes.cast(data, ctypes.POINTER(ctypes.c_byte)))
    out = _DATA_BLOB()
    if ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(blob), None, None, None, None, 0, ctypes.byref(out)):
        result = ctypes.string_at(out.pbData, out.cbData)
        ctypes.windll.kernel32.LocalFree(out.pbData)
        return result
    raise ctypes.WinError()

# ---------- TPM (NCrypt DPAPI-NG, 绑定芯片) ----------
_NCRYPT_AVAIL = None
def _tpm_protect(data):
    global _NCRYPT_AVAIL
    if _NCRYPT_AVAIL is False:
        return dpapi_protect(data)
    try:
        ncrypt = ctypes.WinDLL('ncrypt')
        ncrypt.NCryptProtectSecret.restype = wintypes.DWORD
        ncrypt.NCryptProtectSecret.argtypes = [
            ctypes.c_void_p, wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_byte), wintypes.DWORD,
            wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.POINTER(ctypes.POINTER(ctypes.c_byte)),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        pbData = (ctypes.c_byte * len(data)).from_buffer_copy(data)
        ppbOut = ctypes.POINTER(ctypes.c_byte)()
        pcbOut = wintypes.DWORD(0)
        desc = "LOCAL=user"
        r = ncrypt.NCryptProtectSecret(None, None, pbData, len(data), desc, 0,
            ctypes.byref(ppbOut), ctypes.byref(pcbOut), None)
        if r != 0:
            raise ctypes.WinError(r)
        result = ctypes.string_at(ppbOut, pcbOut.value)
        ncrypt.NCryptFreeBuffer(ppbOut)
        _NCRYPT_AVAIL = True
        return result
    except:
        _NCRYPT_AVAIL = False
        return dpapi_protect(data)

def _tpm_unprotect(data):
    global _NCRYPT_AVAIL
    if _NCRYPT_AVAIL is False:
        return dpapi_unprotect(data)
    try:
        ncrypt = ctypes.WinDLL('ncrypt')
        ncrypt.NCryptUnprotectSecret.restype = wintypes.DWORD
        ncrypt.NCryptUnprotectSecret.argtypes = [
            ctypes.c_void_p, wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_byte), wintypes.DWORD,
            wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.POINTER(ctypes.POINTER(ctypes.c_byte)),
            ctypes.POINTER(wintypes.DWORD),
        ]
        pbData = (ctypes.c_byte * len(data)).from_buffer_copy(data)
        ppbOut = ctypes.POINTER(ctypes.c_byte)()
        pcbOut = wintypes.DWORD(0)
        r = ncrypt.NCryptUnprotectSecret(None, None, pbData, len(data), None, 0,
            ctypes.byref(ppbOut), ctypes.byref(pcbOut))
        if r != 0:
            raise ctypes.WinError(r)
        result = ctypes.string_at(ppbOut, pcbOut.value)
        ncrypt.NCryptFreeBuffer(ppbOut)
        _NCRYPT_AVAIL = True
        return result
    except:
        _NCRYPT_AVAIL = False
        return dpapi_unprotect(data)

def generate_device_key():
    raw = secrets.token_bytes(1024)
    n = int.from_bytes(raw, 'big')
    chars = DEVICE_KEY_ALPHABET
    result = []
    while n > 0:
        n, r = divmod(n, len(chars))
        result.append(chars[r])
    return ''.join(result)

# ==================== HK Pair（R1→TPM芯片密封, R2→加密用, 注册表存储） ====================
def _hk_read_r1(rp):
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, rp)
        raw, t = winreg.QueryValueEx(k, REG_HK_R1)
        winreg.CloseKey(k)
        if t == winreg.REG_BINARY:
            return _tpm_unprotect(bytes(raw))
    except: pass
    return None

def _hk_write_r1(data, rp):
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, rp, 0, winreg.KEY_SET_VALUE)
        blob = _tpm_protect(data)
        winreg.SetValueEx(k, REG_HK_R1, 0, winreg.REG_BINARY, blob)
        winreg.CloseKey(k)
        return True
    except: return False

def _hk_gen_pad(r1, reg6, out_len=1024):
    reg6_str = '|'.join(str(x) for x in reg6).encode()
    h = hashlib.sha256(r1 + reg6_str).digest()
    pad = bytearray(h)
    while len(pad) < out_len:
        h = hashlib.sha256(h).digest()
        pad.extend(h)
    return bytes(pad[:out_len])

def _hk_ensure_pair(rp=None):
    if rp is None: rp = REG_PATH
    if _hk_read_r1(rp):
        return True
    r1 = secrets.token_bytes(1024)
    r2 = generate_device_key()
    rv = reg_read_sys_vals(rp)
    if not rv:
        return False
    r2_bytes = r2.encode('utf-8')
    pad = _hk_gen_pad(r1, rv, len(r2_bytes))
    wrapped = bytes(a ^ b for a, b in zip(r2_bytes, pad))
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, rp, 0, winreg.KEY_SET_VALUE)
        blob = dpapi_protect(wrapped)
        winreg.SetValueEx(k, REG_HK_PAIR, 0, winreg.REG_BINARY, blob)
        winreg.CloseKey(k)
        _hk_write_r1(r1, rp)
        return True
    except:
        return False

# ==================== nbnn256（62-base b + 1024bit Z + 256轮大数） ====================
_N62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
def _b62_int(s):
    n=0
    for c in s: n=n*62+_N62.index(c)
    return n
def _int_b62(n):
    if n==0: return _N62[0]
    c=[]
    while n>0: n,r=divmod(n,62); c.append(_N62[r])
    return ''.join(reversed(c))
def _b62_slice(b_sq_62, start, end):
    if len(b_sq_62) >= end: return b_sq_62[start:end]
    return b_sq_62[start:]
def _nbnn256_header(Z_hex, enc_time, ipv4, ipv6, n_orig_len, u_len, hm):
    return (f"=== NBNN256 v1 ===\nZ:{Z_hex}\nenc_time:{enc_time}\n"
            f"ipv4:{ipv4}\nipv6:{ipv6}\nhm:{hm}\nn_orig_len:{n_orig_len}\nu_len:{u_len}\n"
            f"---DATA---\n")

def nbnn256_encrypt(data, b_str=None, Z_hex=None):
    n_bytes = data.encode() if isinstance(data, str) else data
    n = int.from_bytes(n_bytes, 'big')
    n_orig_len = len(n_bytes)
    if b_str is None:
        b_str = ''.join(secrets.choice(_N62) for _ in range(512))
    b_int = _b62_int(b_str)
    if Z_hex:
        Z_bytes = bytes.fromhex(Z_hex)
    else:
        Z_bytes = secrets.token_bytes(32)
    Z_int = int.from_bytes(Z_bytes, 'big')
    y = (b_int + Z_int - 1) // Z_int
    b_bits = bin(b_int)[2:]
    if len(b_bits) < 256: b_bits = b_bits.zfill(256)
    b_top256 = [int(c) for c in b_bits[:256]]
    b_sq_int = b_int * b_int
    b_sq_62 = _int_b62(b_sq_int)
    b62_seg = _b62_slice(b_sq_62, 13, 998)
    seg_int = _b62_int(b62_seg) if b62_seg else 0
    tb = -869302789; sc = 688867200; nw = int(datetime.datetime.now().timestamp())
    ipv4 = socket.gethostbyname(socket.gethostname()) if hasattr(socket, 'gethostbyname') else "0.0.0.0"
    try: ipv6 = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)[0][4][0]
    except: ipv6 = "::1"
    ipv4_int = int.from_bytes(socket.inet_pton(socket.AF_INET, ipv4), 'big') if ipv4 != "0.0.0.0" else 0
    try: ipv6_int = int.from_bytes(socket.inet_pton(socket.AF_INET6, ipv6), 'big')
    except: ipv6_int = 0
    vars5 = [nw, tb + int.from_bytes(Z_bytes[:1],'big') + nw,
             sc + int.from_bytes(Z_bytes[-1:],'big'), ipv4_int + ipv6_int, b_int * Z_int]
    U_parts = []
    for x in range(256):
        xi = x; rv = vars5[x % 5]
        imul = (xi * 0x9E3779B9) & 0xFFFFFFFF
        s = (xi*y + b_int*xi + seg_int + xi + b_int - n + xi + (xi - y) + (b_int-n)*xi + n + xi + xi + imul) * rv
        if b_top256[x]:
            s += Z_int
        else:
            s -= Z_int
        s_bytes = s.to_bytes(max((abs(s).bit_length() + 8) // 8, 1), 'big', signed=True)
        prefix = len(s_bytes).to_bytes(4, 'big')
        U_parts.append(prefix + s_bytes)
    U_all = b''.join(U_parts)
    u_len = len(U_all)
    hm = max(u_len * 8 // 2, 1)
    Z_base = Z_bytes
    z_pad_needed = hm - len(Z_base)
    if z_pad_needed > 0:
        Z_base += b'\x00' * z_pad_needed
    interleaved = bytearray()
    up, zp = 0, 0
    while up < len(U_all) or zp < len(Z_base):
        if up < len(U_all):
            chunk = U_all[up:up+1]; interleaved.extend(chunk); up += 1
        if zp < len(Z_base):
            chunk = Z_base[zp:zp+1]; interleaved.extend(chunk); zp += 1
    hdr = {"Z": Z_bytes.hex(), "enc_time": nw, "ipv4": ipv4, "ipv6": ipv6,
           "hm": hm, "n_orig_len": n_orig_len, "u_len": u_len}
    return bytes(interleaved), b_str, hdr

def nbnn256_decrypt(cipher_bytes, b_str, hdr):
    b_int = _b62_int(b_str)
    b_bits = bin(b_int)[2:]
    if len(b_bits) < 256: b_bits = b_bits.zfill(256)
    b_top256 = [int(c) for c in b_bits[:256]]
    b_sq_int = b_int * b_int
    b_sq_62 = _int_b62(b_sq_int)
    b62_seg = _b62_slice(b_sq_62, 13, 998)
    seg_int = _b62_int(b62_seg) if b62_seg else 0
    Z_bytes = bytes.fromhex(hdr.get('Z', ''))
    Z_int = int.from_bytes(Z_bytes, 'big')
    hm = int(hdr.get('hm', 1))
    n_orig_len = int(hdr.get('n_orig_len', 0))
    u_len = int(hdr.get('u_len', 0))
    enc_time = int(hdr.get('enc_time', '0'))
    ipv4 = hdr.get('ipv4', '0.0.0.0')
    ipv6 = hdr.get('ipv6', '::1')
    y = (b_int + Z_int - 1) // Z_int
    tb = -869302789; sc = 688867200; nw = enc_time
    ipv4_int = int.from_bytes(socket.inet_pton(socket.AF_INET, ipv4), 'big') if ipv4 != '0.0.0.0' else 0
    try: ipv6_int = int.from_bytes(socket.inet_pton(socket.AF_INET6, ipv6), 'big')
    except: ipv6_int = 0
    vars5 = [nw, tb + int.from_bytes(Z_bytes[:1],'big') + nw,
             sc + int.from_bytes(Z_bytes[-1:],'big'), ipv4_int + ipv6_int, b_int * Z_int]
    # byte-level deinterleave
    U_bytes = bytearray(); z_extracted = bytearray()
    for i in range(0, len(cipher_bytes), 2):
        if i < len(cipher_bytes): U_bytes.append(cipher_bytes[i])
        if i + 1 < len(cipher_bytes): z_extracted.append(cipher_bytes[i+1])
    U_bytes = bytes(U_bytes)[:u_len]
    if Z_int and (len(z_extracted) < len(Z_bytes) or int.from_bytes(bytes(z_extracted)[:len(Z_bytes)], 'big') != Z_int):
        raise ValueError(f"nbnn256: Z mismatch")
    U_vals = []; off = 0
    for x in range(256):
        if off + 4 > len(U_bytes): raise ValueError("nbnn256: truncated length prefix")
        sz = int.from_bytes(U_bytes[off:off+4], 'big')
        off += 4
        if off + sz > len(U_bytes): raise ValueError("nbnn256: truncated value")
        val = int.from_bytes(U_bytes[off:off+sz], 'big', signed=True)
        off += sz
        U_vals.append(val)
    def _recover_sx(x):
        if b_top256[x]:
            return U_vals[x] - Z_int
        else:
            return U_vals[x] + Z_int
    sum0_full = _recover_sx(0)
    sum1_full = _recover_sx(1)
    sum0_s = sum0_full // vars5[0]
    sum1_s = sum1_full // vars5[1]
    numerator = sum0_s - sum1_s + 2*b_int + y + 5 + 0x9E3779B9
    if numerator < 0:
        raise ValueError("nbnn256: invalid n numerator")
    n_int = numerator
    if n_int <= 0:
        raise ValueError("nbnn256: n <= 0")
    ok = True
    for x in (0, 1, 2, 3, 255):
        xi = x; rv = vars5[x % 5]
        imul = (xi * 0x9E3779B9) & 0xFFFFFFFF
        s_check = (xi*y + b_int*xi + seg_int + xi + b_int - n_int + xi + (xi - y) + (b_int-n_int)*xi + n_int + xi + xi + imul) * rv
        if b_top256[x]:
            s_check += Z_int
        else:
            s_check -= Z_int
        if s_check != U_vals[x]:
            ok = False; break
    if ok:
        n_bytes = n_int.to_bytes((n_int.bit_length()+7)//8, 'big')
        if n_orig_len > 0 and len(n_bytes) < n_orig_len:
            n_bytes = b'\x00' * (n_orig_len - len(n_bytes)) + n_bytes
        try: return n_bytes.decode()
        except: return n_bytes
    raise ValueError("nbnn256 decrypt: integrity check failed")

def _nbnn_write_b(b_str):
    blob = _tpm_protect(b_str.encode())
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(k, REG_NBNN_B, 0, winreg.REG_BINARY, blob)
    winreg.CloseKey(k)

def _nbnn_read_b():
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH)
    raw, t = winreg.QueryValueEx(k, REG_NBNN_B)
    winreg.CloseKey(k)
    if t == winreg.REG_BINARY:
        return _tpm_unprotect(bytes(raw)).decode()
    return None

def _build_nbnn_output(cd_bytes, meta_dict, b_str=None):
    """Encrypt meta_dict with nbnn256, write file: 密文 section + IFON= line."""
    meta_serial = json.dumps(meta_dict, ensure_ascii=False, default=str).encode()
    interleaved, b_str, nbnn_hdr = nbnn256_encrypt(meta_serial, b_str)
    interleaved = lzma.compress(interleaved)
    cd_b64 = base64.b64encode(cd_bytes).decode()
    info_b64 = base64.b64encode(interleaved).decode()
    lines = ["=== NBNN256 v2 ===", "【密文】"]
    for i in range(0, len(cd_b64), 76): lines.append(cd_b64[i:i+76])
    lines.append("---NBNN-INFO---")
    for k in ("Z","enc_time","ipv4","ipv6","hm","n_orig_len","u_len"):
        if k in nbnn_hdr: lines.append(f"{k}:{nbnn_hdr[k]}")
    lines.append(f"IFON={info_b64}")
    lines.append("============\n")
    return '\n'.join(lines), b_str

def _parse_nbnn_output(text):
    """Parse NBNN256 v2 file: returns (cd_bytes, info_bytes, nbnn_hdr).
    info_bytes is the nbnn256-interleaved data from IFON=."""
    lines = text.split('\n')
    section = None; cd_b64 = []; nbnn_hdr = {}; info_b64 = None
    for s in [l.strip() for l in lines]:
        if s == '【密文】': section = 'cd'; continue
        if s == '---NBNN-INFO---': section = 'nbnn'; continue
        if s.startswith('IFON='):
            info_b64 = s[5:]
            continue
        if s.startswith('===') and 'NBNN256' in s: continue
        if s == '============': continue
        if section == 'cd' and s: cd_b64.append(s)
        elif section == 'nbnn' and ':' in s:
            k, v = s.split(':', 1)
            nbnn_hdr[k.strip()] = v.strip()
    cd_bytes = base64.b64decode(''.join(cd_b64))
    if not info_b64:
        raise ValueError("Missing IFON= line in nbnn256 v2 file")
    info_bytes = base64.b64decode(info_b64)
    info_bytes = lzma.decompress(info_bytes)
    return cd_bytes, info_bytes, nbnn_hdr

# ==================== SecureStore（DPAPI 加密存储全部敏感值） ====================
def _write_secure_store(k, vals, rand, dk_plain):
    payload = json.dumps({
        "v0": vals[0], "v1": vals[1], "v2": vals[2],
        "v3": vals[3], "v4": vals[4],
        "rand": rand,
        "dk": dk_plain,
    }, separators=(",", ":")).encode()
    blob = dpapi_protect(payload)
    winreg.SetValueEx(k, REG_STORE, 0, winreg.REG_BINARY, blob)

def _read_secure_store(rp=None):
    if rp is None: rp = REG_PATH
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, rp)
        raw, t = winreg.QueryValueEx(k, REG_STORE)
        winreg.CloseKey(k)
        if t != winreg.REG_BINARY: return None
        data = json.loads(dpapi_unprotect(bytes(raw)))
        return data
    except:
        return None

def get_device_key():
    r1 = _hk_read_r1(REG_PATH)
    if r1:
        try:
            rv = reg_read_sys_vals()
            if rv:
                k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH)
                hk_raw, hk_type = winreg.QueryValueEx(k, REG_HK_PAIR)
                winreg.CloseKey(k)
                if hk_type == winreg.REG_BINARY:
                    wrapped = dpapi_unprotect(bytes(hk_raw))
                    pad = _hk_gen_pad(r1, rv, len(wrapped))
                    r2_bytes = bytes(a ^ b for a, b in zip(wrapped, pad)).decode('utf-8')
                    return r2_bytes
        except: pass
    data = _read_secure_store()
    if data and "dk" in data: return data["dk"]
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH)
        dk_val, dk_type = winreg.QueryValueEx(k, REG_DEV_KEY)
        winreg.CloseKey(k)
        if dk_type == winreg.REG_BINARY:
            return dpapi_unprotect(bytes(dk_val)).decode()
        return dk_val
    except:
        return None

def reg_read_sys_vals(rp=None):
    if rp is None: rp = globals().get("REG_PATH", REG_PATH)
    data = _read_secure_store(rp)
    if data:
        rv = (data["v0"], data["v1"], data["v2"], data["v3"], data["v4"])
        if "rand" in data: rv = rv + (data["rand"],)
        return rv
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, rp)
        v0 = int(winreg.QueryValueEx(k, "SysVolSN")[0], 16)
        v1 = int(winreg.QueryValueEx(k, "SysInstallTS")[0])
        v2 = winreg.QueryValueEx(k, "BiosSN")[0]
        v3 = winreg.QueryValueEx(k, "WinSID")[0]
        v4 = winreg.QueryValueEx(k, "CpuSN")[0]
        try: v5 = winreg.QueryValueEx(k, REG_RAND)[0]
        except FileNotFoundError: v5 = None
        winreg.CloseKey(k)
        if v5: return (v0, v1, v2, v3, v4, v5)
        return (v0, v1, v2, v3, v4)
    except:
        return None

def reg_init_onetime():
    _RP = REG_PATH
    # 尝试读 SecureStore
    data = _read_secure_store(_RP)
    if data:
        rv = (data["v0"], data["v1"], data["v2"], data["v3"], data["v4"], data.get("rand", ""))
        if not data.get("dk"):
            data["dk"] = generate_device_key()
            try:
                k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RP, 0, winreg.KEY_SET_VALUE)
                _write_secure_store(k, (data["v0"],data["v1"],data["v2"],data["v3"],data["v4"]), data["rand"], data["dk"])
                winreg.CloseKey(k)
            except: pass
        _hk_ensure_pair(_RP)
        return rv
    # 尝试旧格式迁移
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RP)
        winreg.QueryValueEx(k, REG_FLAG)
        winreg.CloseKey(k)
        rv = reg_read_sys_vals(_RP)
        if rv:
            v0, v1, v2, v3, v4 = rv[0], rv[1], rv[2], rv[3], rv[4]
            rand = rv[5] if len(rv) == 6 else _gen_master_rand(v0, v1, v2, v3, v4)
            dk = get_device_key() or generate_device_key()
            k2 = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RP, 0, winreg.KEY_SET_VALUE)
            _write_secure_store(k2, (v0, v1, v2, v3, v4), rand, dk)
            winreg.CloseKey(k2)
            print("🔐 迁移至 SecureStore(DPAPI全量保护)完成")
            _hk_ensure_pair(_RP)
            return (v0, v1, v2, v3, v4, rand)
        return rv
    except FileNotFoundError:
        pass
    # 首次运行
    print("🆕 首次运行，生成环境指纹...")
    try:
        vals = []
        vs = ctypes.c_uint32()
        ctypes.windll.kernel32.GetVolumeInformationA(b"C:\\", None, 0, ctypes.byref(vs), None, None, None, 0)
        vals.append(vs.value)
        tk = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        ts = winreg.QueryValueEx(tk, "InstallDate")[0]; vals.append(ts); winreg.CloseKey(tk)
        vals.append(get_bios_sn())
        gk = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
        sid = winreg.QueryValueEx(gk, "MachineGuid")[0]; winreg.CloseKey(gk); vals.append(sid)
        vals.append(get_cpu_sn())
        rand = _gen_master_rand(vals[0], vals[1], vals[2], vals[3], vals[4])
        dk_plain = generate_device_key()
        k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, _RP)
        _write_secure_store(k, vals, rand, dk_plain)
        winreg.SetValueEx(k, REG_FLAG, 0, winreg.REG_SZ, "1")
        winreg.CloseKey(k)
        print("🔒 环境指纹+8192bit密钥 DPAPI 固化完成")
        _hk_ensure_pair(_RP)
        return (vals[0], vals[1], vals[2], vals[3], vals[4], rand)
    except Exception as e:
        print(f"❌ 注册表写入失败：{e}"); return None

# ==================== KDF（v3.2 基准原样，rv5 保护） ====================
def derive_key(pwd, fp, kdf_type="argon2"):
    pwd_part = pwd[:128]
    rv = fp.get("reg_sys_vals")
    if rv is None: raise ValueError("reg_sys_vals 为空")
    t = fp.get("t", "")
    rv5 = rv[5] if len(rv) == 6 else "0" * 60
    # 读 DK（独立字段，不被 pwd[:128] 截断）
    dev_key = fp.get("dev_key", "")
    base = (
        f"{pwd_part}|{t}|{fp.get('mac',0)}|{fp.get('ip',192168001)}|{fp.get('temp',61)}"
        f"|{fp.get('gold',2035)}|{fp.get('cpu','unknown_cpu')[:50]}|{fp.get('gpu','unknown_gpu')[:50]}"
        f"|{fp.get('lat',DEFAULT_LAT)}|{fp.get('lon',DEFAULT_LON)}"
        f"|{fp.get('soviet_offset',0)}|{fp.get('trump_offset',0)}"
        f"|QQ:{'|'.join(map(str,fp.get('encrypt_qq',[])))[:256]}"
        f"|MAIL:{'|'.join(map(str,fp.get('encrypt_mail',[])))[:256]}"
        f"|FIX_VOL:{rv[0]}|FIX_TS:{rv[1]}|FIX_BIOS:{rv[2]}"
        f"|FIX_SID:{rv[3]}|FIX_CPU:{rv[4]}|FIX_RAND:{rv5}"
        f"|DEV_KEY:{dev_key}"
    ).encode()
    salt = f"{fp.get('mac',0)}|{fp.get('ip',192168001)}|{rv[0]}|{rv[2]}|{rv5}".encode()[:64]
    if kdf_type == "argon2" and HAS_ARGON2:
        return _hash_secret_raw(secret=base, salt=salt,
            time_cost=ARGON_TIME_COST, memory_cost=ARGON_MEM_COST,
            parallelism=ARGON_PARALLELISM, hash_len=HASH_LEN, type=_Type.ID)
    return hashlib.pbkdf2_hmac('sha256', base, salt, 100000, dklen=HASH_LEN)

# ==================== 工具（v3.2 基准原样） ====================
def hmac_sha256(pwd, plain):
    import hmac
    return hmac.new(pwd.encode(), plain.encode(), 'sha256').hexdigest()
def gen_interfere():
    return hashlib.sha256(secrets.randbits(240).to_bytes(30,'big')).hexdigest()
def norm_path(p): return os.path.normpath(p.strip().strip('"').strip("'"))
def save_file(name, content):
    if os.path.exists(name):
        name = f"{os.path.splitext(name)[0]}_{datetime.datetime.now():%H%M%S}.txt"
    with open(name, 'w', encoding='utf-8') as f: f.write(content)
    print(f"💾 {os.path.abspath(name)}")
def save_contact(qq, mail):
    if not qq and not mail: return
    p = os.path.join(os.path.expandvars('%APPDATA%'), 'jm', '加密号.txt')
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'a', encoding='utf-8') as f:
        f.write(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] QQ:{'|'.join(qq)} MAIL:{'|'.join(mail)}\n")
    print(f"📇 已保存：{p}")
def parse_contacts(s):
    qq, mail = [], []
    for t in re.split(r'[,\s;]+', s.strip()):
        t = t.strip()
        if re.fullmatch(r'\d{5,11}', t): qq.append(t)
        elif '@' in t and '.' in t: mail.append(t)
    return qq, mail

# ==================== 加密（v3.2 基准原样） ====================
def encrypt_flow(plaintext, pwd, fp, hash_only=False):
    rv = fp["reg_sys_vals"]
    if not rv: raise ValueError("固化指纹缺失")
    kdf_t = "argon2" if HAS_ARGON2 else "pbkdf2"
    seed = derive_key(pwd, fp, kdf_t)
    rng = random.Random(seed)
    idxs = [rng.randint(0,11) for _ in range(12)]
    params = [rng.randint(1,255) for _ in range(12)]
    sub_seeds = [rng.randint(0, 2**32-1) if i in SEED_DEP_LAYERS else 0 for i in idxs]
    xor_var = rng.randbytes(1024)
    data = plaintext.encode()
    data = bytes(data[i] ^ xor_var[i % 1024] for i in range(len(data)))
    for i in range(12):
        data = BYTE_LAYERS[idxs[i]][0](data, params[i], sub_seeds[i])
    sha = hmac_sha256(pwd, plaintext)
    meta = {**fp, "idx": idxs, "params": params, "sub_seeds": sub_seeds,
            "sha256": sha, "hash_only": hash_only, "kdf": kdf_t,
            "layer_mode": "byte", "compress": False,
            "xor8192": base64.b64encode(xor_var).decode()}
    return sha, meta, (None if hash_only else data)

# ==================== 解密 byte+char 双兼容，三阶段 seed（v3.2 基准原样） ====================
def _decrypt_byte(payload, pwd, meta, rv):
    def _seed_current(rv_override):
        meta["reg_sys_vals"] = rv_override
        kdf_t = meta.get("kdf", "pbkdf2")
        try:
            rv5_info = rv_override[5] if len(rv_override) == 6 else "0"*60
            print(f"  debug seed(rv6): mac={meta.get('mac')} ip={meta.get('ip')} rv_len={len(rv_override)} rv5={rv5_info[:16]}...")
            return derive_key(pwd, meta, kdf_t)
        except Exception as e:
            print(f"  debug seed ERR: {e}")
            return f"ERR:{e}"
    def _seed_legacy(rv5):
        meta["reg_sys_vals"] = rv5
        pwd_part = pwd[:128]; _rv = rv5
        t = meta.get("t", "")
        mac = meta.get("mac", 0); ip = meta.get("ip", 192168001)
        temp = meta.get("temp", 61); gold = meta.get("gold", 2035)
        cpu = meta.get("cpu", "unknown_cpu")[:50]; gpu = meta.get("gpu", "unknown_gpu")[:50]
        lat = meta.get("lat", DEFAULT_LAT); lon = meta.get("lon", DEFAULT_LON)
        so = meta.get("soviet_offset", 0); tr = meta.get("trump_offset", 0)
        qq = "|".join(map(str, meta.get("encrypt_qq",[])))[:256]
        mail = "|".join(map(str, meta.get("encrypt_mail",[])))[:256]
        base = (
            f"{pwd_part}|{t}|{mac}|{ip}|{temp}|{gold}|{cpu}|{gpu}|{lat}|{lon}"
            f"|{so}|{tr}|QQ:{qq}|MAIL:{mail}"
            f"|FIX_VOL:{_rv[0]}|FIX_TS:{_rv[1]}|FIX_BIOS:{_rv[2]}"
            f"|FIX_SID:{_rv[3]}|FIX_CPU:{_rv[4]}"
        ).encode()
        salt = f"{mac}|{ip}|{_rv[0]}|{_rv[2]}".encode()[:64]
        kdf_t = meta.get("kdf", "pbkdf2")
        if kdf_t == "argon2" and HAS_ARGON2:
            return _hash_secret_raw(secret=base, salt=salt,
                time_cost=ARGON_TIME_COST, memory_cost=ARGON_MEM_COST,
                parallelism=ARGON_PARALLELISM, hash_len=HASH_LEN, type=_Type.ID)
        return hashlib.pbkdf2_hmac("sha256", base, salt, 100000, dklen=HASH_LEN)
    def _check(seed, label=""):
        rng = random.Random(seed)
        e_idxs = [rng.randint(0,11) for _ in range(12)]
        e_params = [rng.randint(1,255) for _ in range(12)]
        e_ss = [rng.randint(0,2**32-1) if i in SEED_DEP_LAYERS else 0 for i in e_idxs]
        ok = True
        if e_idxs != meta.get("idx",[]):
            print(f"❌ 层序不对({label})")
            print(f"  debug: exp={e_idxs[:6]}... got={meta.get('idx',[])[:6]}...")
            ok = False
        if e_params != meta.get("params",[]):
            print(f"❌ 参数不对({label})")
            print(f"  debug: exp={e_params[:6]}... got={meta.get('params',[])[:6]}...")
            ok = False
        if e_ss != meta.get("sub_seeds",[]):
            print(f"❌ 子seed不对({label})")
            print(f"  debug: exp={e_ss[:6]}... got={meta.get('sub_seeds',[])[:6]}...")
            ok = False
        if not ok: return None
        return (e_idxs, e_params, e_ss)
    # ① rv6
    seed = _seed_current(rv)
    if not (isinstance(seed, str) and seed.startswith("ERR:")):
        r = _check(seed, "rv6")
        if r:
            e_idxs, e_params, e_ss = r
            try:
                data = payload
                for i in reversed(range(12)):
                    data = BYTE_LAYERS[meta["idx"][i]][1](data, meta["params"][i], meta["sub_seeds"][i])
                if meta.get("xor8192"):
                    try:
                        xv = base64.b64decode(meta["xor8192"])
                        data = bytes(data[j] ^ xv[j % 1024] for j in range(len(data)))
                    except: pass
                plain = data.decode("utf-8", errors="replace")
                if meta.get("sha256") and hmac_sha256(pwd, plain) != meta["sha256"]:
                    print("⚠️ SHA256失败"); return f"[干扰]{gen_interfere()}"
                if meta.get("sha256"): print("✅ SHA256通过")
                return plain
            except Exception as e:
                print(f"❌ 解密出错：{e}"); return f"[干扰]{gen_interfere()}()"
    # ② rv5fake
    if rv and len(rv) == 6:
        rv5fake = (rv[0], rv[1], rv[2], rv[3], rv[4], "0"*60)
        seed2 = _seed_current(rv5fake)
        if not (isinstance(seed2, str) and seed2.startswith("ERR:")):
            r = _check(seed2, "rv5fake")
            if r:
                e_idxs, e_params, e_ss = r
                try:
                    data = payload
                    for i in reversed(range(12)):
                        data = BYTE_LAYERS[meta["idx"][i]][1](data, meta["params"][i], meta["sub_seeds"][i])
                    if meta.get("xor8192"):
                        try:
                            xv = base64.b64decode(meta["xor8192"])
                            data = bytes(data[j] ^ xv[j % 1024] for j in range(len(data)))
                        except: pass
                    plain = data.decode("utf-8", errors="replace")
                    if meta.get("sha256") and hmac_sha256(pwd, plain) != meta["sha256"]:
                        print("⚠️ SHA256失败"); return f"[干扰]{gen_interfere()}"
                    if meta.get("sha256"): print("✅ SHA256通过(rv5fake)")
                    return plain
                except Exception as e:
                    print(f"❌ 解密出错：{e}"); return f"[干扰]{gen_interfere()}()"
    # ③ legacy
    if rv and len(rv) >= 5:
        rv5 = (rv[0], rv[1], rv[2], rv[3], rv[4])
        try:
            seed3 = _seed_legacy(rv5)
            r = _check(seed3, "legacy")
            if r:
                e_idxs, e_params, e_ss = r
                try:
                    data = payload
                    for i in reversed(range(12)):
                        data = BYTE_LAYERS[meta["idx"][i]][1](data, meta["params"][i], meta["sub_seeds"][i])
                    if meta.get("xor8192"):
                        try:
                            xv = base64.b64decode(meta["xor8192"])
                            data = bytes(data[j] ^ xv[j % 1024] for j in range(len(data)))
                        except: pass
                    plain = data.decode("utf-8", errors="replace")
                    if meta.get("sha256") and hmac_sha256(pwd, plain) != meta["sha256"]:
                        print("⚠️ SHA256失败"); return f"[干扰]{gen_interfere()}"
                    if meta.get("sha256"): print("✅ SHA256通过(legacy)")
                    return plain
                except Exception as e:
                    print(f"❌ 解密出错：{e}"); return f"[干扰]{gen_interfere()}()"
        except Exception as e:
            print(f"❌ legacy KDF失败：{e}")
    # ④ hk_legacy（旧版 hk 文件：DK 走 pwd[:128] 截断，无 DEV_KEY 字段）
    try:
        hk_dk = get_device_key()
        if hk_dk and pwd == "____HK_MODE____":
            meta2 = dict(meta)
            meta2.pop("dev_key", None)
            meta2["reg_sys_vals"] = rv
            kdf_t = meta2.get("kdf", "pbkdf2")
            seed4 = derive_key(hk_dk, meta2, kdf_t)
            if not (isinstance(seed4, str) and seed4.startswith("ERR:")):
                r = _check(seed4, "hk_legacy")
                if r:
                    e_idxs, e_params, e_ss = r
                    data = payload
                    for i in reversed(range(12)):
                        data = BYTE_LAYERS[meta["idx"][i]][1](data, meta["params"][i], meta["sub_seeds"][i])
                    if meta.get("xor8192"):
                        try:
                            xv = base64.b64decode(meta["xor8192"])
                            data = bytes(data[j] ^ xv[j % 1024] for j in range(len(data)))
                        except: pass
                    plain = data.decode("utf-8", errors="replace")
                    if meta.get("sha256") and hmac_sha256(hk_dk, plain) != meta["sha256"]:
                        print("⚠️ SHA256失败"); return f"[干扰]{gen_interfere()}"
                    if meta.get("sha256"): print("✅ SHA256通过(hk_legacy)")
                    return plain
    except:
        pass
    return f"[干扰]{gen_interfere()}"


def _decrypt_char(payload, pwd, meta, rv):
    meta["reg_sys_vals"] = rv
    pwd_part = pwd[:128]
    mac = meta.get("mac", 0); ip = meta.get("ip", 192168001)
    temp = meta.get("temp", 61); gold = meta.get("gold", 2035)
    cpu = meta.get("cpu", "unknown_cpu")[:50]; gpu = meta.get("gpu", "unknown_gpu")[:50]
    lat = meta.get("lat", DEFAULT_LAT); lon = meta.get("lon", DEFAULT_LON)
    so = meta.get("soviet_offset", 0); tr = meta.get("trump_offset", 0)
    qq = "|".join(map(str, meta.get("encrypt_qq",[])))[:256]
    mail = "|".join(map(str, meta.get("encrypt_mail",[])))[:256]
    base = (
        f"{pwd_part}|{mac}|{ip}|{temp}|{gold}|{cpu}|{gpu}|{lat}|{lon}|{so}|{tr}"
        f"|QQ:{qq}|MAIL:{mail}"
    ).encode()
    salt = f"{mac}|{ip}".encode()[:64]
    seed = hashlib.pbkdf2_hmac("sha256", base, salt, 100000, dklen=16)
    rng = random.Random(seed)
    e_idxs = [rng.randint(0,11) for _ in range(12)]
    if e_idxs != meta.get("idx",[]): print("❌ 层序不对(char)"); return f"[干扰]{gen_interfere()}"
    try:
        data = payload
        for i in reversed(range(12)):
            li = meta["idx"][i]
            if li == 11:
                rot_shift = meta.get("rot", [0]*12)[i]
                data = _old_dec_rot(data, rot_shift)
            else:
                data = OLD_DEC_MAP[li](data)
        plain = data.decode("utf-8", errors="replace")
        if meta.get("sha256") and hmac_sha256(pwd, plain) != meta["sha256"]:
            print("⚠️ SHA256失败(char)"); return f"[干扰]{gen_interfere()}"
        if meta.get("sha256"): print("✅ SHA256通过(char)")
        return plain
    except Exception as e:
        print(f"❌ 旧char解密出错：{e}"); return f"[干扰]{gen_interfere()}"


def decrypt_flow(payload, pwd, meta):
    rv = reg_read_sys_vals()
    if not rv: print("❌ 注册表指纹缺失"); return f"[干扰]{gen_interfere()}"
    mode = meta.get("layer_mode", "char")
    if mode == "byte":
        return _decrypt_byte(payload, pwd, meta, rv)
    else:
        return _decrypt_char(payload, pwd, meta, rv)

# ==================== 文件IO ====================
def build_output(cd, sha, meta, ho):   ### 修③
    lines = [
        f"加密人QQ: {', '.join(meta.get('encrypt_qq',[]))}",
        f"加密人邮箱: {', '.join(meta.get('encrypt_mail',[]))}",
        f"加密时间: {meta['t']}",
        f"偏移_苏联: {meta['soviet_offset']}",
        f"偏移_特朗普: {meta['trump_offset']}",
        f"金价: {meta['gold']}",
        f"硬盘UUID: {meta['disk_uuid']}",
        f"CPU: {meta['cpu']}",
        f"GPU: {meta['gpu']}",
        f"坐标: {meta['lat']},{meta['lon']}",
        f"MAC: {format(meta['mac'], '012X')}",
        f"IP段: {meta['ip']}",
        f"温度: {meta['temp']}",
        f"KDF: {meta.get('kdf')}",
        f"混淆: {meta.get('layer_mode')}",
        f"压缩: {meta.get('compress')}",
        f"XOR8192: {meta.get('xor8192', False)}",
        f"层序: {','.join(map(str, meta['idx']))}",
        f"参数: {','.join(map(str, meta['params']))}",
        f"子种: {','.join(map(str, meta['sub_seeds']))}",
    ]
    if ho: return f"=== HASH ===\nSHA256: {sha}\n---INFO---\n" + "\n".join(lines) + "\n============\n"
    b64 = base64.b64encode(cd).decode()
    bl = [b64[i:i+76] for i in range(0, len(b64), 76)]
    return f"=== ENCRYPTED ===\n【密文】\n" + "\n".join(bl) + f"\n---INFO---\n" + "\n".join(lines) + "\n============\n"

def build_fk_output(cd, sha, meta, wrapped_key_b64):
    lines = [
        f"加密时间: {meta['t']}",
        f"偏移_苏联: {meta['soviet_offset']}",
        f"偏移_特朗普: {meta['trump_offset']}",
        f"金价: {meta['gold']}",
        f"硬盘UUID: {meta['disk_uuid']}",
        f"CPU: {meta['cpu']}",
        f"GPU: {meta['gpu']}",
        f"坐标: {meta['lat']},{meta['lon']}",
        f"MAC: {format(meta['mac'], '012X')}",
        f"IP段: {meta['ip']}",
        f"温度: {meta['temp']}",
        f"KDF: {meta.get('kdf')}",
        f"混淆: {meta.get('layer_mode')}",
        f"压缩: {meta.get('compress')}",
        f"XOR8192: {meta.get('xor8192', False)}",
        f"层序: {','.join(map(str, meta['idx']))}",
        f"参数: {','.join(map(str, meta['params']))}",
        f"子种: {','.join(map(str, meta['sub_seeds']))}",
    ]
    b64 = base64.b64encode(cd).decode()
    bl = [b64[i:i+76] for i in range(0, len(b64), 76)]
    return f"=== ENCRYPTED ===\n【文件密钥】\n{wrapped_key_b64}\n【密文】\n" + "\n".join(bl) + f"\n---INFO---\n" + "\n".join(lines) + "\n============\n"


def parse_integrated(path):   ### 修④
    with open(path, 'r', encoding='utf-8') as f: content = f.read()
    meta = {"encrypt_qq":[], "encrypt_mail":[], "t": datetime.datetime.now().strftime("%Y%m%d%H%M%S"),
           "mac":0, "ip":192168001, "temp":61, "gold":2035,
           "cpu":"unknown_cpu", "gpu":"unknown_gpu", "lat":DEFAULT_LAT, "lon":DEFAULT_LON,
           "soviet_offset":0, "trump_offset":0, "disk_uuid":"",
           "layer_mode":"char", "compress":False, "kdf":"pbkdf2",
            "idx":[], "params":[], "sub_seeds":[], "sha256":None, "hash_only":False,
            "xor8192":"", "rot":[0]*12}
    cl = []; inc = False; pending_sha = False; fk = None; inc_fk = False
    content = content.replace('：', ':')
    for line in content.split('\n'):
        s = line.strip()
        if pending_sha and s:
            meta["sha256"] = s; pending_sha = False
        if s.startswith('【SHA256】'):
            rest = s.split('【SHA256】')[1].strip()
            if rest:
                meta["sha256"] = rest
            else:
                pending_sha = True
        if s == '【密文】': inc = True; inc_fk = False; continue
        if s == '【文件密钥】': inc_fk = True; continue
        if s.startswith('【') and s.endswith('】'): inc = False; inc_fk = False; continue
        if s == '---INFO---': inc = False; inc_fk = False
        if inc_fk and s: fk = s
        if inc and s: cl.append(s)
        if ':' in s:
            k, v = s.split(':', 1)[0].strip(), s.split(':', 1)[1].strip()
            if k == 'CPU': meta['cpu'] = v
            elif k == 'GPU': meta['gpu'] = v
            elif k == '坐标': meta['lat'], meta['lon'] = map(float, v.split(','))
            elif k == 'MAC': meta['mac'] = int(v, 16) if not v.isdigit() else int(v)
            elif k == 'IP段': meta['ip'] = int(v)
            elif k == '温度': meta['temp'] = int(v)
            elif k == '金价': meta['gold'] = int(v)
            elif k == '硬盘UUID': meta['disk_uuid'] = v
            elif k == '加密人QQ': meta['encrypt_qq'] = [x.strip() for x in v.split(',') if x.strip()]
            elif k == '加密人邮箱': meta['encrypt_mail'] = [x.strip() for x in v.split(',') if x.strip()]
            elif k == '加密时间': meta['t'] = v
            elif k == '偏移_苏联': meta['soviet_offset'] = int(v)
            elif k == '偏移_特朗普': meta['trump_offset'] = int(v)
            elif k == 'KDF': meta['kdf'] = v
            elif k == '混淆': meta['layer_mode'] = v
            elif k == '压缩': meta['compress'] = v.lower() == 'true'
            elif k == 'XOR8192': meta['xor8192'] = v
            elif k == '层序': meta['idx'] = [int(x) for x in v.split(',') if x]       ### 修④a
            elif k == '参数': meta['params'] = [int(x) for x in v.split(',') if x]   ### 修④b
            elif k == '子种': meta['sub_seeds'] = [int(x) for x in v.split(',') if x] ### 修④c
    if meta['mac'] == 0 or meta['ip'] == 192168001 or meta['temp'] == 61:
        m = re.search(r'MAC:\s*(\d+)\s*IP段:\s*(\d+)\s*温度:\s*(\d+)', content)
        if m: meta['mac'], meta['ip'], meta['temp'] = int(m[1]), int(m[2]), int(m[3])
    meta['hash_only'] = (not cl)
    if fk:
        try:
            meta['file_key'] = dpapi_unprotect(base64.b64decode(fk)).decode()
        except:
            meta['file_key'] = None
    return meta, ''.join(cl)

# ==================== -cz ====================
def cz_mode():
    print(f"\n⚠️  -cz：将清除 HKCU\\{REG_PATH}，此前所有加密文件将无法解密！")
    confirm = input("确认清除？(y/N): ").strip().lower()
    if confirm != 'y': print("已取消"); return
    rv = reg_read_sys_vals()
    if rv:
        bak_dir = os.path.join(os.path.expandvars('%APPDATA%'), 'jm')
        os.makedirs(bak_dir, exist_ok=True)
        bak_path = os.path.join(bak_dir, f"JMEncrypt_backup_{datetime.datetime.now():%Y%m%d_%H%M%S}.json")
        bak_data = {
            "SYS_VOL": rv[0], "SYS_TS": rv[1], "BIOS": rv[2], "SID": rv[3], "CPU": rv[4],
            "RAND": rv[5] if len(rv) == 6 else None,
            "DEV_KEY": get_device_key(),
            "REG_PATH": REG_PATH,
            "BACKUP_TIME": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        with open(bak_path, 'w', encoding='utf-8') as f: json.dump(bak_data, f, indent=2, ensure_ascii=False)
        print(f"📦 旧指纹已备份 → {bak_path}")
    else:
        print("ℹ️ 当前无固化指纹，跳过备份")
    r = subprocess.run(f'reg delete HKCU\\software\\{REG_PATH} /f', shell=True, capture_output=True, text=True)
    if r.returncode == 0: print("✅ 注册表指纹已清除")
    else: print(f"⚠️ reg.exe 清失败: {r.stderr.strip()}")
    # ==================== 交互（修⑥ encrypt_mode 收 except 完整） ====================
def hk_encrypt():
    try:
        dk = get_device_key()
        if not dk: print("❌ 设备密钥未初始化"); return
        print("\n--- 硬件密钥加密(仅本机) ---")
        fp = norm_path(input("📄 明文：").strip())
        if not os.path.exists(fp): print("❌ 不存在"); return
        txt = open(fp, 'r', encoding='utf-8').read()
        mac = uuid.getnode(); ip = get_ip(); temp = fetch_max_temp(); gold = fetch_gold_price()
        cpu = get_cpu_model(); du = get_disk_serial()
        so = int((datetime.datetime.now() - datetime.datetime(1991, 12, 26)).total_seconds())
        tr = int((datetime.datetime.now() - datetime.datetime(1946, 6, 14)).total_seconds())
        t = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        rv = reg_init_onetime()
        if not rv: print("❌ 指纹缺失"); return
        fp_ = {"t": t, "mac": mac, "ip": ip, "temp": temp, "gold": gold,
               "disk_uuid": du, "cpu": cpu, "gpu": "unknown_gpu",
               "lat": DEFAULT_LAT, "lon": DEFAULT_LON,
               "soviet_offset": so, "trump_offset": tr,
               "encrypt_qq": [], "encrypt_mail": [], "reg_sys_vals": rv,
                "dev_key": dk}
        pwd = "____HK_MODE____"
        sha, meta, cd = encrypt_flow(txt, pwd, fp_, False)
        want_nbnn = input("🔹 追加 nbnn256 可逆封板？(y/N): ").strip().lower() == 'y'
        if want_nbnn:
            _8192_r1 = _gen_8192_store()
            cd = bytes(cd[i] ^ _8192_r1[i % 1024] for i in range(len(cd)))
            text, b_str = _build_nbnn_output(cd, {**meta, "sha256": sha})
            try: _nbnn_write_b(b_str); print("🔑 nbnn256密钥已密封至TPM")
            except Exception as e: print(f"⚠️ TPM密封失败({e})，密钥仅存本会话")
            fname = f"{os.path.splitext(os.path.basename(fp))[0]}_hk_nbnn.txt"
            save_file(fname, text)
        else:
            fname = f"{os.path.splitext(os.path.basename(fp))[0]}_hk_encrypted.txt"
            save_file(fname, build_output(cd, sha, meta, False))
        print("✅ 硬件密钥加密完成（仅本机可解）")
    except Exception as e:
        print(f"❌ 加密失败：{e}"); traceback.print_exc()

def hk_decrypt():
    try:
        print("\n--- 本机解密(自动识别文件类型) ---")
        fp = norm_path(input("📄 加密文件：").strip())
        if not os.path.isfile(fp): print("❌ 文件不存在"); return
        with open(fp, 'r', encoding='utf-8') as f: content = f.read()
        if '=== NBNN256 v2 ===' in content or '=== NBNN256 v1 ===' in content:
            cd_bytes, info_bytes, nbnn_hdr = _parse_nbnn_output(content)
            try:
                _8192_r1 = _read_8192_r1()
                cd_bytes = bytes(cd_bytes[i] ^ _8192_r1[i % 1024] for i in range(len(cd_bytes)))
            except: pass
            b_str = None
            try: b_str = _nbnn_read_b(); print("🔑 nbnn256 密钥从TPM加载")
            except: pass
            if not b_str:
                b_input = input("🔹 nbnn256 b密钥(留空从TPM): ").strip()
                if b_input: b_str = b_input
            if not b_str: print("❌ 无nbnn256密钥"); return
            try:
                meta_bytes = nbnn256_decrypt(info_bytes, b_str, nbnn_hdr)
                meta = json.loads(meta_bytes)
                dk = get_device_key()
                pwd = "____HK_MODE____" if (dk and meta.get("dev_key")) else input("🔑 内层密码：").strip()
                if not pwd: print("❌ 空密码"); return
                plain = decrypt_flow(cd_bytes, pwd, meta)
                if not plain.startswith("[干扰]"):
                    save_file(f"{os.path.splitext(os.path.basename(fp))[0]}_decrypted.txt", plain)
                    print(f"✅ nbnn256+HK 解密成功，预览：{plain[:80]}")
                    return
                print(plain); return
            except ValueError as e:
                print(f"❌ nbnn256 解密失败：{e}")
                return
        meta, b64s = parse_integrated(fp)
        if meta.get('hash_only'): print("❌ 仅哈希"); return
        if not b64s: print("❌ 空密文"); return

        dk = get_device_key()
        if dk:
            meta["dev_key"] = dk
            plain = decrypt_flow(base64.b64decode(b64s), "____HK_MODE____", meta)
            if not plain.startswith("[干扰]"):
                save_file(f"{os.path.splitext(os.path.basename(fp))[0]}_decrypted.txt", plain)
                print(f"✅ 解密成功，预览：{plain[:80]}")
                return

        fk = meta.get('file_key')
        if fk:
            plain = decrypt_flow(base64.b64decode(b64s), fk, meta)
            if not plain.startswith("[干扰]"):
                save_file(f"{os.path.splitext(os.path.basename(fp))[0]}_decrypted.txt", plain)
                print(f"✅ 解密成功(文件密钥)，预览：{plain[:80]}")
                return

        print("❌ 解密失败：无匹配密钥")
        print("   - 本机加密 → 需同一台机器 + 同一用户")
        print("   - 文件密钥加密 → 需同一台机器")
    except Exception as e:
        print(f"❌ 解密失败：{e}"); traceback.print_exc()

# ==================== 文件密钥模式（每文件独立8192bit密钥） ====================
def fk_encrypt():
    try:
        dk = get_device_key()
        if not dk: print("❌ 设备密钥未初始化"); return
        print("\n--- 文件密钥加密(每文件独立8192bit) ---")
        fp = norm_path(input("📄 明文：").strip())
        if not os.path.exists(fp): print("❌ 不存在"); return
        txt = open(fp, 'r', encoding='utf-8').read()
        mac = uuid.getnode(); ip = get_ip(); temp = fetch_max_temp(); gold = fetch_gold_price()
        cpu = get_cpu_model(); du = get_disk_serial()
        so = int((datetime.datetime.now() - datetime.datetime(1991, 12, 26)).total_seconds())
        tr = int((datetime.datetime.now() - datetime.datetime(1946, 6, 14)).total_seconds())
        t = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        rv = reg_init_onetime()
        if not rv: print("❌ 指纹缺失"); return
        file_key = generate_device_key()
        wrapped = base64.b64encode(dpapi_protect(file_key.encode())).decode()
        fp_ = {"t": t, "mac": mac, "ip": ip, "temp": temp, "gold": gold,
               "disk_uuid": du, "cpu": cpu, "gpu": "unknown_gpu",
               "lat": DEFAULT_LAT, "lon": DEFAULT_LON,
               "soviet_offset": so, "trump_offset": tr,
               "encrypt_qq": [], "encrypt_mail": [], "reg_sys_vals": rv}
        sha, meta, cd = encrypt_flow(txt, file_key, fp_, False)
        fname = hashlib.sha256(cd[:20]).hexdigest() + ".jmf"
        save_file(fname, build_fk_output(cd, sha, meta, wrapped))
        print(f"✅ 文件密钥加密完成（密钥已写入文件，仅本机可解）")
    except Exception as e:
        print(f"❌ 加密失败：{e}"); traceback.print_exc()

def fk_decrypt():
    try:
        print("\n--- 文件密钥解密 ---")
        fpath = norm_path(input("📄 .jmf 文件：").strip())
        if not os.path.exists(fpath): print("❌ 不存在"); return
        meta, b64s = parse_integrated(fpath)
        if meta.get('hash_only'): print("❌ 仅哈希"); return
        if not b64s: print("❌ 空密文"); return
        fk = meta.get('file_key')
        if not fk: print("❌ 文件密钥缺失或非本机加密"); return
        plain = decrypt_flow(base64.b64decode(b64s), fk, meta)
        if plain.startswith("[干扰]"): print(plain); return
        save_file(f"{os.path.splitext(os.path.basename(fpath))[0]}_decrypted.txt", plain)
        print(f"✅ 解密成功，预览：{plain[:80]}")
    except Exception as e:
        print(f"❌ 解密失败：{e}"); traceback.print_exc()

def encrypt_mode(auto_qq=False):
    try:
        print("\n--- 加密 ---")
        pwd = input("🔑 密码：").strip()
        if not pwd: print("❌ 空密码"); return
        fp = norm_path(input("📄 明文：").strip())
        if not os.path.exists(fp): print("❌ 不存在"); return
        txt = open(fp, 'r', encoding='utf-8').read()
        print("⏳ 采环境...")
        mac = uuid.getnode(); ip = get_ip(); temp = fetch_max_temp(); gold = fetch_gold_price()
        cpu = get_cpu_model(); bios = get_bios_sn()
        du = get_disk_serial()
        so = int((datetime.datetime.now() - datetime.datetime(1991, 12, 26)).total_seconds())
        tr = int((datetime.datetime.now() - datetime.datetime(1946, 6, 14)).total_seconds())
        t = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        qq, mail = [], []
        if auto_qq:
            qi = input("🔹 QQ：").strip(); mi = input("🔹 Mail：").strip()
            qq, _ = parse_contacts(qi); _, mail = parse_contacts(mi)
            if qq or mail: save_contact(qq, mail)
        rv = reg_init_onetime()
        if not rv: print("❌ 指纹缺失"); return
        fp_ = {"t": t, "mac": mac, "ip": ip, "temp": temp, "gold": gold,
               "disk_uuid": du, "cpu": cpu, "gpu": "unknown_gpu",
               "lat": DEFAULT_LAT, "lon": DEFAULT_LON,
               "soviet_offset": so, "trump_offset": tr,
               "encrypt_qq": qq, "encrypt_mail": mail, "reg_sys_vals": rv}
        print("⏳ 加密中...")
        sha, meta, cd = encrypt_flow(txt, pwd, fp_, False)
        want_nbnn = input("🔹 追加 nbnn256 可逆封板？(y/N): ").strip().lower() == 'y'
        if want_nbnn:
            _8192_r1 = _gen_8192_store()
            cd = bytes(cd[i] ^ _8192_r1[i % 1024] for i in range(len(cd)))
            text, b_str = _build_nbnn_output(cd, {**meta, "sha256": sha})
            try: _nbnn_write_b(b_str); print("🔑 nbnn256密钥已密封至TPM")
            except Exception as e: print(f"⚠️ TPM密封失败({e})，密钥仅存本会话")
            fname = f"{os.path.splitext(os.path.basename(fp))[0]}_nbnn.txt"
            save_file(fname, text)
        else:
            fname = f"{os.path.splitext(os.path.basename(fp))[0]}_encrypted.txt"
            save_file(fname, build_output(cd, sha, meta, False))
        print(f"✅ 完成 {fname}")
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_SET_VALUE)
            blob = _tpm_protect(pwd.encode())
            winreg.SetValueEx(k, REG_PWD_BOX, 0, winreg.REG_BINARY, blob)
            winreg.CloseKey(k)
        except: pass
    except Exception as e:
        print(f"❌ 加密失败：{e}"); traceback.print_exc()


def decrypt_mode():
    try:
        print("\n--- 解密 ---")
        fp = norm_path(input("📄 加密文件：").strip())
        if not os.path.isfile(fp): print("❌ 文件不存在"); return
        with open(fp, 'r', encoding='utf-8') as f: content = f.read()
        if '=== NBNN256 v2 ===' in content or '=== NBNN256 v1 ===' in content:
            cd_bytes, info_bytes, nbnn_hdr = _parse_nbnn_output(content)
            try:
                _8192_r1 = _read_8192_r1()
                cd_bytes = bytes(cd_bytes[i] ^ _8192_r1[i % 1024] for i in range(len(cd_bytes)))
            except: pass
            b_str = None
            try: b_str = _nbnn_read_b(); print("🔑 nbnn256 密钥从TPM加载")
            except: pass
            if not b_str:
                b_input = input("🔹 nbnn256 b密钥(留空从TPM): ").strip()
                if b_input: b_str = b_input
            if not b_str: print("❌ 无nbnn256密钥"); return
            try:
                meta_bytes = nbnn256_decrypt(info_bytes, b_str, nbnn_hdr)
                meta = json.loads(meta_bytes)
                pwd = "____HK_MODE____" if meta.get("dev_key") else input("🔑 内层密码：").strip()
                if not pwd: print("❌ 空密码"); return
                dk = get_device_key()
                if dk and pwd == "____HK_MODE____": meta["dev_key"] = dk
                plain = decrypt_flow(cd_bytes, pwd, meta)
                if not plain.startswith("[干扰]"):
                    save_file(f"{os.path.splitext(os.path.basename(fp))[0]}_decrypted.txt", plain)
                    print(f"✅ nbnn256 解密成功，预览：{plain[:80]}")
                    return
                print(plain); return
            except ValueError as e:
                print(f"❌ nbnn256 解密失败：{e}")
                return
        # Normal format
        meta, b64s = parse_integrated(fp)
        if meta.get('hash_only'): print("❌ 仅哈希"); return
        if not b64s: print("❌ 空密文"); return
        pwd = None
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH)
            raw, t = winreg.QueryValueEx(k, REG_PWD_BOX)
            winreg.CloseKey(k)
            if t == winreg.REG_BINARY:
                pwd = _tpm_unprotect(bytes(raw)).decode()
        except: pass
        if pwd:
            plain = decrypt_flow(base64.b64decode(b64s), pwd, meta)
            if not plain.startswith("[干扰]"):
                save_file(f"{os.path.splitext(os.path.basename(fp))[0]}_decrypted.txt", plain)
                print(f"✅ 解密成功（TPM密码），预览：{plain[:80]}")
                return
        pwd = input("🔑 密码：").strip()
        if not pwd: print("❌ 空密码"); return
        plain = decrypt_flow(base64.b64decode(b64s), pwd, meta)
        if plain.startswith("[干扰]"): print(plain); return
        save_file(f"{os.path.splitext(os.path.basename(fp))[0]}_decrypted.txt", plain)
        print(f"✅ 解密成功，预览：{plain[:80]}")
    except Exception as e:
        print(f"❌ 解密失败：{e}"); traceback.print_exc()


def verify_mode():
    try:
        print("\n--- 验证 ---")
        pwd = input("🔑 密码：").strip()
        if not pwd: print("❌ 空密码"); return
        pf = norm_path(input("📄 明文：").strip())
        mf = norm_path(input("📄 元数据：").strip())
        if not os.path.exists(pf) or not os.path.exists(mf): print("❌ 不存在"); return
        txt = open(pf, 'r', encoding='utf-8').read()
        meta, _ = parse_integrated(mf)
        if meta.get("sha256"):
            if hmac_sha256(pwd, txt) == meta["sha256"]: print("✅ 验证成功")
            else: print("❌ 验证失败")
        else:
            print("ℹ️ 文件中无SHA256信息，无法验证")
    except Exception as e:
        print(f"❌ 验证失败：{e}"); traceback.print_exc()


# ==================== ECC（secp256k1 ECIES，最后包装） ====================
def ecc_keygen():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    priv = ec.generate_private_key(ec.SECP256K1())
    priv_bytes = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    blob = _tpm_protect(priv_bytes)
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(k, REG_EC_KEY, 0, winreg.REG_BINARY, blob)
    winreg.CloseKey(k)
    pub = priv.public_key()
    return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

def ecc_load_priv():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH)
    raw, t = winreg.QueryValueEx(k, REG_EC_KEY)
    winreg.CloseKey(k)
    if t != winreg.REG_BINARY: return None
    return serialization.load_der_private_key(_tpm_unprotect(bytes(raw)), None)

def ecc_get_pubkey():
    priv = ecc_load_priv()
    if not priv: return None
    from cryptography.hazmat.primitives import serialization
    return priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

def _gen_8192_store():
    R1 = secrets.token_bytes(1024)
    R2 = secrets.token_bytes(1024)
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(k, REG_8192_R2, 0, winreg.REG_BINARY, dpapi_protect(R2))
    winreg.SetValueEx(k, REG_8192_R1R2, 0, winreg.REG_BINARY, _tpm_protect(R1 + R2))
    winreg.CloseKey(k)
    return R1

def _read_8192_r1():
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH)
    raw, t = winreg.QueryValueEx(k, REG_8192_R1R2)
    winreg.CloseKey(k)
    return _tpm_unprotect(bytes(raw))[:1024]

def ecc_encrypt(data, pubkey_pem):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import serialization, hashes
    import struct
    pub = serialization.load_pem_public_key(pubkey_pem.encode())
    ephem = ec.generate_private_key(ec.SECP256K1())
    shared = ephem.exchange(ec.ECDH(), pub)
    dk = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"JMEncrypt-ECIES").derive(shared)
    aes = AESGCM(dk)
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, data, None)
    ephem_der = ephem.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(struct.pack(">H", len(ephem_der)) + ephem_der + nonce + ct).decode()

def ecc_decrypt(data_b64):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import serialization, hashes
    import struct
    raw = base64.b64decode(data_b64)
    elen = struct.unpack(">H", raw[:2])[0]
    ephem_der = raw[2:2+elen]
    nonce = raw[2+elen:2+elen+12]
    ct = raw[2+elen+12:]
    ephem_pub = serialization.load_der_public_key(ephem_der)
    priv = ecc_load_priv()
    shared = priv.exchange(ec.ECDH(), ephem_pub)
    dk = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"JMEncrypt-ECIES").derive(shared)
    aes = AESGCM(dk)
    return aes.decrypt(nonce, ct, None)

def ecc_genkey_mode():
    print("\n--- ECC 生成密钥对 ---")
    try:
        pub_pem = ecc_keygen()
        print("✅ EC密钥对已生成，私钥已密封至注册表(TPM)")
        print(f"\n公钥(Public Key):\n{pub_pem}")
        save = input("保存公钥到文件？(pub.pem): ").strip()
        if not save: save = "pub.pem"
        with open(save, 'w', encoding='utf-8') as f: f.write(pub_pem)
        print(f"💾 公钥已保存: {os.path.abspath(save)}")
    except Exception as e:
        print(f"❌ {e}"); traceback.print_exc()

def ecc_encrypt_mode():
    try:
        print("\n--- ECC 加密 ---")
        pub_fp = norm_path(input("📄 接收方公钥(.pem): ").strip())
        if not os.path.isfile(pub_fp): print("❌ 不存在"); return
        with open(pub_fp, 'r', encoding='utf-8') as f: pub_pem = f.read()
        fp = norm_path(input("📄 明文: ").strip())
        if not os.path.exists(fp): print("❌ 不存在"); return
        txt = open(fp, 'r', encoding='utf-8').read()
        key = secrets.token_hex(32)
        rv = reg_init_onetime()
        if not rv: print("❌ 指纹缺失"); return
        fp_ = {"t": datetime.datetime.now().strftime("%Y%m%d%H%M%S"), "mac": uuid.getnode(), "ip": get_ip(),
               "temp": fetch_max_temp(), "gold": fetch_gold_price(), "disk_uuid": get_disk_serial(),
               "cpu": get_cpu_model(), "gpu": "unknown_gpu", "lat": DEFAULT_LAT, "lon": DEFAULT_LON,
               "soviet_offset": int((datetime.datetime.now()-datetime.datetime(1991,12,26)).total_seconds()),
               "trump_offset": int((datetime.datetime.now()-datetime.datetime(1946,6,14)).total_seconds()),
               "encrypt_qq": [], "encrypt_mail": [], "reg_sys_vals": rv}
        sha, meta, cd = encrypt_flow(txt, key, fp_, False)
        _8192_r1 = _gen_8192_store()
        cd = bytes(cd[i] ^ _8192_r1[i % 1024] for i in range(len(cd)))
        nbnn_text, b_str = _build_nbnn_output(cd, {**meta, "sha256": sha})
        wrapped_b = ecc_encrypt(b_str.encode(), pub_pem)
        lines = ["=== ECC ENCRYPTED ===", "【ECC密钥】"]
        for i in range(0, len(wrapped_b), 76): lines.append(wrapped_b[i:i+76])
        lines.append(nbnn_text)
        fname = f"{os.path.splitext(os.path.basename(fp))[0]}_ecc_encrypted.txt"
        save_file(fname, '\n'.join(lines))
        print("✅ ECC加密完成，仅持有对应私钥者可解密")
    except Exception as e:
        print(f"❌ {e}"); traceback.print_exc()

def ecc_decrypt_mode():
    try:
        print("\n--- ECC 解密 ---")
        fp = norm_path(input("📄 加密文件: ").strip())
        if not os.path.isfile(fp): print("❌ 不存在"); return
        with open(fp, 'r', encoding='utf-8') as f: content = f.read()
        if '=== ECC ENCRYPTED ===' not in content: print("❌ 不是ECC格式"); return
        section = None; wrapped_b = ""; nbnn_lines = []
        for line in content.split('\n'):
            s = line.strip()
            if s == '【ECC密钥】': section = 'ecc_key'; continue
            if s == '=== NBNN256 v2 ===': section = 'nbnn_body'; nbnn_lines.append(s); continue
            if section == 'ecc_key' and s and not s.startswith('==='): wrapped_b += s
            elif section == 'nbnn_body': nbnn_lines.append(s)
        if not wrapped_b: print("❌ 无ECC密钥段"); return
        b_str = ecc_decrypt(wrapped_b).decode()
        nbnn_text = '\n'.join(nbnn_lines)
        cd_bytes, info_bytes, nbnn_hdr = _parse_nbnn_output(nbnn_text)
        _8192_r1 = _read_8192_r1()
        cd_bytes = bytes(cd_bytes[i] ^ _8192_r1[i % 1024] for i in range(len(cd_bytes)))
        meta_bytes = nbnn256_decrypt(info_bytes, b_str, nbnn_hdr)
        meta = json.loads(meta_bytes)
        pwd = "____HK_MODE____" if meta.get("dev_key") else input("🔑 内层密码: ").strip()
        if not pwd: print("❌ 空密码"); return
        dk = get_device_key()
        if dk and pwd == "____HK_MODE____": meta["dev_key"] = dk
        plain = decrypt_flow(cd_bytes, pwd, meta)
        if not plain.startswith("["):
            save_file(f"{os.path.splitext(os.path.basename(fp))[0]}_decrypted.txt", plain)
            print(f"✅ ECC解密成功，预览: {plain[:80]}")
        else:
            print(plain)
    except Exception as e:
        print(f"❌ {e}"); traceback.print_exc()

# ==================== main ====================
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-qq', action='store_true', help='直进加密+QQ/Mail')
    parser.add_argument('-cz', action='store_true', help='清注册表指纹并重新生成（旧文件将失效）')
    parser.add_argument('-hk', action='store_true', help='硬件密钥模式（8192bit设备绑定密钥，无需输入密码，推荐）')
    parser.add_argument('-ecc', action='store_true', help='椭圆曲线密钥模式（secp256k1 ECIES，私钥TPM密封）')
    args = parser.parse_args()

    if args.cz:
        cz_mode()
        rv = reg_init_onetime()
        if rv:
            print(f"✅ 新指纹: VOL={rv[0]:08X}, BIOS={rv[2][:20]}..., RAND={rv[5][:8]}...")
        else:
            print("❌ 重新生成失败")
        input("按回车退出")
        sys.exit(0)

    try:
        if args.hk:
            dk = get_device_key()
            if not dk: print("❌ 设备密钥未初始化"); input("按回车退出"); sys.exit(1)
            print(f"🔑 硬件密钥已就绪（{len(dk)}字符/8192bit熵）")
            while True:
                print("\n🔐 封板 v3.4-hk（8192bit设备密钥，仅本机可用）")
                print("1.硬件加密 2.硬件解密 3.退")
                c = input("> ").strip()
                if c == '1': hk_encrypt(); input("\n回车继续")
                elif c == '2': hk_decrypt(); input("\n回车继续")
                elif c == '3': break
        elif args.ecc:
            priv = ecc_load_priv()
            if not priv:
                print("⚠️ 未检测到EC密钥，请先生成")
                ecc_genkey_mode()
                input("\n回车继续")
            while True:
                print("\n🔐 封板 v3.5-ecc（12层+ nbnn256 + secp256k1 ECIES）")
                print("1.生成密钥对 2.ECC加密 3.ECC解密 4.退")
                c = input("> ").strip()
                if c == '1': ecc_genkey_mode(); input("\n回车继续")
                elif c == '2': ecc_encrypt_mode(); input("\n回车继续")
                elif c == '3': ecc_decrypt_mode(); input("\n回车继续")
                elif c == '4': break
        elif args.qq:
            encrypt_mode(auto_qq=True)
        else:
            dk = get_device_key()
            while True:
                print("\n🔐 封板 v3.5-hkfix（8192bit设备密钥+DPAPI+文件密钥+nbnn256）")
                print("1.加密 2.解密 3.验证 4.退")
                if dk: print("5.本机加密(8192bit) 6.本机解密(自动识别)")
                c = input("> ").strip()
                if c == '1': encrypt_mode(False); input("\n回车继续")
                elif c == '2': decrypt_mode(); input("\n回车继续")
                elif c == '3': verify_mode(); input("\n回车继续")
                elif c == '4': break
                elif c == '5' and dk: hk_encrypt(); input("\n回车继续")
                elif c == '6' and dk: hk_decrypt(); input("\n回车继续")
    except Exception as e:
        print(f"💥 {e}"); traceback.print_exc()
    finally:
        input("按回车退出")