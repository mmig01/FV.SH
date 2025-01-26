import numpy as np


f = [1 , 2]
g = [3, 4]
x = [1] + [0] * (2 - 1) + [1]
mul = np.polymul(f, g)
print("f(x) = \n", np.poly1d(mul))
print("x = \n", np.poly1d(x))

result, mod = np.polydiv(mul, x)
print("result = \n", np.poly1d(result))
print("mod = \n", np.poly1d(mod))

