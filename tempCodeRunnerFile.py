  print("================== bootstrapping 전 ==================") 
    print("파라미터 설정")
    print("q = ", q, "t = ", t, "delta = ", math.floor(q / t))
    # 다항식 계수에 packing
    packed_plaintext1 = [6]
    # 다항식 암호화
    ciphertext = fv_mod_q.encrypt(pk=fv_mod_q.public_key, m=packed_plaintext1)
    
    # 부트스트래핑 전 덧셈, 곱셈
    before_bootstrapping(ciphertext=ciphertext)

    print("================== bootstrapping ==================") 
    
    
    enc_mul_result = ciphertext
    for i in range(5):
        enc_mul_result = fv_mod_q.multiply_use_rlk_ver1(ct1=ciphertext, ct2=enc_mul_result, T=T, rlk=fv_mod_q.relinearisation_key)
        bootstrapping_result = bootstrapping(ciphertext=enc_mul_result)
        enc_mul_result = bootstrapping_result
        dec_mul_ciphertext = fv_mod_q.decrypt(enc_mul_result)
        print(f"{i + 1} 번 곱셈 후 곱셈 결과 다항식 복호화 결과 : \n", dec_mul_ciphertext)