import math
import numpy as np
from fv_scheme import fv_scheme
from parameters.polynomial_ring import PolynomialRing

# cyclotomic 다항식의 차수
# f(x) = x^n + 1
n = pow(2, 1)
# 평문, 암호문 모듈러스
q = pow(2 ,40)
t = 10000
delta = math.floor(q / t)

print("q = ", q, "t = ", t, "delta = ", delta)


fv = fv_scheme.FV_SH(degree=n, pt_modulus=t, ct_modulus=q)
s = fv.secret_key

# 공개 키
pk = fv.generate_public_key()
ct1 = fv.encrypt(pk = pk ,m = [140])
pt1 = fv.decrypt(ct = ct1)
print ("복호화 결과: \n", np.poly1d(pt1))

ct2 = fv.encrypt(pk = pk ,m = [20])
pt2 = fv.decrypt(ct = ct2)
print ("복호화 결과: \n", np.poly1d(pt2))

T = 2

rlk = fv.generate_relinearisation_version1_key(T=T)
mul = fv.multiply_use_rlk_ver1(ct1=ct1, ct2=ct2, T=T, rlk=rlk)
dec = fv.decrypt(mul)
print("재선형화 1 을 이용한 곱셈 복호화 : ", np.poly1d(dec))

p = pow(2, 120)
rlk2 = fv.generate_relinearisation_version2_key(p=p)
mul2 = fv.multiply_use_rlk_ver2(ct1=ct1, ct2=ct2, p=p, rlk=rlk2)
dec2 = fv.decrypt(mul2)
print("재선형화 2 을 이용한 곱셈 복호화 : ", np.poly1d(dec2))




