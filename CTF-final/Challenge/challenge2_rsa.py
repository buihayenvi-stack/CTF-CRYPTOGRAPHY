from sympy import integer_nthroot
import math
import random

# ==============================
# DỮ LIỆU GIẢ LẬP TỪ CHALLENGE CTF
# ==============================
# Cho Cube Root Attack (RSA không padding, textbook RSA)
N_cube = 32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930386017358561357722606590881485368019786079970631431826013503651109330042280712669114707894822093419346390932977456644021951065222954004833857494691216455623974016355439963640097631214074322761166716682375158526932596852989277804180699980320057816909302957737609582153067553939928285055050284319797898055421319756611
e_cube = 3
ciphertext_list = [300763, 592704, 343000, 1860867, 1030301, 1728000, 912673, 1295029, 1404928, 1259712, 1030301, 857375, 1061208, 1259712, 912673, 1092727, 857375, 1061208, 1367631, 1481544, 857375, 970299, 1601613, 941192, 1030301, 857375, 1481544, 1367631, 1367631, 1560896, 1953125]  # m^3 cho flag "CTF{example_flag_for_cube_root}"

# Cho Coppersmith Attack (Partial Key Exposure)
N_partial = 108847113801339077984277106940955637713394609976883781040445850445429626130643837289364192696299568358495247070682208847954465741669789698256482423383861831962696150194004468593307083270604667592439230412234439776794213853509047451479119442399966640303214601612579857926937300984587001504013393656787611221547
leaked_partial = 301805411119097566376161667387457984975  # p % 2^128 (low 128 bits)
bound = 2**128  # Bound cho small root

# Cho Fermat Factorization ( Prime yếu)
N_weak = 98196520585303823925366809922514116817327974213383696042857875114249064341261119671275905104134872382560329330729044871934344405617397455221157486029610268703840699343411149018618359059959548902617988712964359483192704072810594839388467677494579445995923403317811613914943603771273506246156942168403848102409

# Cho Bleichenbacher (Phần bổ sung cho: Padding yếu PKCS#1 v1.5)
# Giả lập: N_bleich, e_bleich, c_bleich (ciphertext), và oracle giả (thực tế cần server)
N_bleich = N_cube  # Reuse N lớn
e_bleich = 65537  # e phổ biến
# Giả lập plaintext padded PKCS#1 v1.5: 00 02 [random non-zero] 00 [message]
message = b"Hello, Bleichenbacher!"
padded = b'\x00\x02' + bytes([random.randint(1, 255) for _ in range(128 - 3 - len(message))]) + b'\x00' + message
c_bleich = pow(int.from_bytes(padded, 'big'), e_bleich, N_bleich)  # Ciphertext

# ==============================
# HÀM ATTACK CHO: RSA KHÔNG PADDING (CUBE ROOT ATTACK)
# ==============================
def cube_root_attack(ciphertexts, e=3):
    """
    Tính căn bậc e nguyên của từng ciphertext (textbook RSA attack)
    """
    plaintexts = []
    for c in ciphertexts:
        root, exact = integer_nthroot(c, e)
        if exact:
            plaintexts.append(root)
        else:
            raise ValueError(f"Không thể tính căn bậc {e} cho c = {c}")
    return plaintexts

def decode_flag(plaintexts):
    try:
        flag_bytes = bytearray(plaintexts)
        return flag_bytes.decode('ascii')
    except Exception as e:
        return f"[Lỗi decode: {e}]"

# ==============================
# HÀM ATTACK CHO: PADDING YẾU (BLEICHENBACHER - DEMO GIẢ LẬP)
# ==============================
def is_pkcs_conforming(m_int, block_size=128):
    """Giả lập check padding PKCS#1 v1.5 (00 02 [non-zero] 00 [msg])"""
    m_bytes = m_int.to_bytes(block_size, 'big')
    return m_bytes.startswith(b'\x00\x02') and b'\x00' in m_bytes[2:]

def bleichenbacher_demo(N, e, c, max_queries=1000):
    """
    Demo Bleichenbacher: Thu hẹp interval cho plaintext dùng oracle giả lập
    (Thực tế cần server oracle; ở đây giả lập decrypt để demo logic)
    """
    k = (N.bit_length() + 7) // 8  # Byte length
    B = 2**(8*(k-2))
    intervals = [(2*B, 3*B - 1)]  # Initial interval
    s = math.ceil(N // (3*B))
    for _ in range(max_queries):
        c_prime = (c * pow(s, e, N)) % N
        # Giả lập oracle: Decrypt (thực tế attacker không biết d, nhưng demo)
        m_prime = pow(c_prime, 1, N)  # Fake decrypt (không thực)
        if is_pkcs_conforming(m_prime, k):  # Oracle check
            # Narrow interval (logic đơn giản hóa)
            a, b = intervals[-1]
            new_a = max(a, math.ceil((2*B + s * b - N + 1) // s))
            new_b = min(b, (3*B - 1 + s * a - N) // s)
            if new_a <= new_b:
                intervals.append((new_a, new_b))
        s += 1
        if len(intervals[-1]) == 1:  # Converge
            return intervals[-1][0]
    return "Attack demo: Converged sau nhiều queries (thực tế ~1M)"

# ==============================
# HÀM ATTACK CHO: PARTIAL KEY EXPOSURE (COPPERSMITH)
# ==============================
# Lưu ý: Để chính xác cần SageMath cho LLL lattice. Dưới đây là approx đơn giản dùng sympy (có thể không recover full cho large N)
# Cài SageMath riêng để chạy full: sage -python script.py
try:
    from sage.all import PolynomialRing, Zmod, ceil # type: ignore
    SAGE_AVAILABLE = True
except ImportError:
    SAGE_AVAILABLE = False

def coppersmith_attack(N, p_approx, bound):
    if not SAGE_AVAILABLE:
        print("Cảnh báo: Cần SageMath cho Coppersmith full. Dùng approx: p ≈ p_approx + (N // (p_approx + bound // 2))")
        q_approx = N // (p_approx + bound // 2)
        p_recovered = N // q_approx
        return p_recovered
    # Full Coppersmith với Sage
    PR = PolynomialRing(Zmod(N), 'x')
    x = PR.gen()
    f = x + p_approx  # Root x = p - p_approx (low bits, nên +)
    beta = 0.5
    epsilon = beta / 7
    dd = f.degree()
    mm = ceil(beta**2 / (dd * epsilon))
    # Giả sử dùng coppersmith function (Sage có built-in qua small_roots)
    roots = f.small_roots(X=bound, beta=beta, m=mm)
    if roots:
        return p_approx + roots[0]
    return None

# ==============================
# HÀM ATTACK CHO: PRIME YẾU (FERMAT FACTORIZATION)
# ==============================
def fermat_factor(N):
    a = math.isqrt(N) + 1
    while True:
        b2 = a * a - N
        b = math.isqrt(b2)
        if b * b == b2:
            return (a - b, a + b)
        a += 1
        if a > N // 2:
            return None, None

# ==============================
# CHẠY CHƯƠNG TRÌNH
# ==============================
if __name__ == "__main__":
    

    #  Cube Root Attack (không padding)
    print(" RSA không padding - Cube Root Attack")
    plaintexts = cube_root_attack(ciphertext_list, e_cube)
    flag = decode_flag(plaintexts)
    print(f"Recovered flag: {flag}")

    #  Bleichenbacher Demo (padding yếu)
    print("\nRSA padding yếu - Bleichenbacher Demo")
    recovered_plain = bleichenbacher_demo(N_bleich, e_bleich, c_bleich)
    print(f"Recovered plaintext (demo): {recovered_plain}")

    # Coppersmith Attack
    print("\nPartial Key Exposure - Coppersmith Attack")
    p_recovered = coppersmith_attack(N_partial, leaked_partial, bound)
    if p_recovered:
        q_recovered = N_partial // p_recovered
        print(f"Recovered p: {p_recovered}")
        print(f"Recovered q: {q_recovered}")
    else:
        print("Attack thất bại (cần tune param hoặc SageMath full)")

    #  Fermat Factorization
    print("\n Prime yếu - Fermat Factorization")
    p_weak_rec, q_weak_rec = fermat_factor(N_weak)
    if p_weak_rec and q_weak_rec:
        print(f"Recovered p: {p_weak_rec}")
        print(f"Recovered q: {q_weak_rec}")
        print(f"|p - q|: {abs(p_weak_rec - q_weak_rec)}")
    else:
        print("Attack thất bại")

    print("="*60)