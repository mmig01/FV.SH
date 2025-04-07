# 다항식의 모든 항을 2진법으로 변환한 후, 가장 하위 비트를 제거
    # def remove_lsb(coef):
    #     x = int(coef)
    #     return float(math.trunc(x / 8) * 8)

    # # 다항식의 계수가 담긴 리스트에 적용하는 예시:
    # def process_polynomial_coeffs(coeff_list):
    #     return [remove_lsb(coef) for coef in coeff_list]
    

    # # 다항식 계수에 LSB 제거
    # enc_plaintext1 = [process_polynomial_coeffs(enc_plaintext1[0]), process_polynomial_coeffs(enc_plaintext1[1])]
    # enc_plaintext2 = [process_polynomial_coeffs(enc_plaintext2[0]), process_polynomial_coeffs(enc_plaintext2[1])]
    # print("int : ", enc_plaintext1)