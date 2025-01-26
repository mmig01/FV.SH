import math
import numpy as np
from fv_scheme import fv_scheme

# cyclotomic 다항식의 차수
# f(x) = x^n + 1
n = pow(2, 4)
# 평문, 암호문 모듈러스
q = pow(2 , 32)
t = 100
delta = math.floor(q / t)
print("q = ", q, "t = ", t, "delta = ", delta)


fv = fv_scheme.FV_SH(degree=n, pt_modulus=t, ct_modulus=q)
s = fv.secret_key

# 공개 키
pk = fv.generate_public_key()
ct = fv.encrypt(pk = pk ,m = [2 , 3 , 4])

pt = fv.decrypt(ct = ct)
print ("복호화 결과: \n", np.poly1d(pt))