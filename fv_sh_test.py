import math
import numpy as np
from fv_scheme import fv_scheme

# cyclotomic 다항식의 차수
# f(x) = x^n + 1
n = pow(2, 1)
# 평문, 암호문 모듈러스
q = pow(2 , 32)
t = 1000
delta = math.floor(q / t)

print("q = ", q, "t = ", t, "delta = ", delta)


fv = fv_scheme.FV_SH(degree=n, pt_modulus=t, ct_modulus=q)
s = fv.secret_key

# 공개 키
pk = fv.generate_public_key()
ct1 = fv.encrypt(pk = pk ,m = [10])
pt1 = fv.decrypt(ct = ct1)
print ("복호화 결과: \n", np.poly1d(pt1))

ct2 = fv.encrypt(pk = pk ,m = [20])
pt2 = fv.decrypt(ct = ct2)
print ("복호화 결과: \n", np.poly1d(pt2))

ct1_ct2 = fv.add(ct1, ct2)
pt1_pt2 = fv.decrypt(ct = ct1_ct2)

print("암호화 후 덧셈 후 복호화 결과 : " , np.poly1d(pt1_pt2))


c0, c1, c2 = fv.multiply(ct1, ct2, [1])

c2s = fv.ring_q._ring_multiply(s, c2)
c1_c2s = fv.ring_q._ring_add(c1, c2s)
dec = fv.decrypt([c0, c1_c2s])

print("곱셈 복호화 : ", np.poly1d(dec))





