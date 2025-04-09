    print("3. digit extraction")
    e = 40
    p = 2
    digit_remove_result = digit_remove(ciphertext=modulus_switching_result, p=p, e=e, v=1, ring=fv_mod_Q)
    print("digit extraction 결과 : \n", digit_remove_result)
   