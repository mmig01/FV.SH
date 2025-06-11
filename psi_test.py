import math
import numpy as np
from fv_scheme import fv_scheme 

n = pow(2, 0)
 # ring q 생성
p = 2
e = 400
q = pow(p, e)
r = 56
t = pow(p, r)
delta = q//t
print("q: ", q, "t: ", t, "delta: ", delta)


pt1 = [6]
pt2 = [5]
d = [1]
fv_mod_q = fv_scheme.FV_SH(degree=n, pt_modulus=t, ct_modulus=q)
print("secret_key: ", fv_mod_q.secret_key)
print("public_key: ", fv_mod_q.public_key)

ct1 = fv_mod_q.encrypt(pk=fv_mod_q.public_key, m=pt1)
print("ct1_dec: ", fv_mod_q.decrypt(ct1))
ct2 = fv_mod_q.encrypt(pk=fv_mod_q.public_key, m=pt2)
print("ct2_dec: ", fv_mod_q.decrypt(ct2))
ct_d = fv_mod_q.encrypt(pk=fv_mod_q.public_key, m=d)
print("ct_d_dec: ", fv_mod_q.decrypt(ct_d))
ct_minus_1 = fv_mod_q.encrypt(pk=fv_mod_q.public_key, m=[-1])
print("ct_minus_1_dec: ", fv_mod_q.decrypt(ct_minus_1))

# a - b
minus_ct2 = [[-coef for coef in ct2[0]], [-coef for coef in ct2[1]]]
ct1_minus_ct2 = fv_mod_q.add(ct1, minus_ct2)


# - d
minus_d = [[-coef for coef in ct_d[0]], [-coef for coef in ct_d[1]]]

# (a-b) - d -1 < 0 ?
result = ct1_minus_ct2
print("c2 - c1: ", result)
print("c2 - c1 dec: ", fv_mod_q.decrypt(result))
result = fv_mod_q.add(result, minus_d)
print("c2 - c1 - d: ", result)
print("c2 - c1 - d dec: ", fv_mod_q.decrypt(result))

result = fv_mod_q.add(result, ct_minus_1)
print("c2 - c1 - d - 1: ", result)
print("c2 - c1 - d - 1 dec: ", fv_mod_q.decrypt(result))

result = [[coef * (1 / t) for coef in result[0]], [coef * (1 / t) for coef in result[1]]]
dec_result = fv_mod_q.decrypt(result)
print("dec_result: ", dec_result)
