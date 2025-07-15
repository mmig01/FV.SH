
    ciphertext = digit_select(ciphertext1=ciphertext, p=p, e=r)
    print("결과 : ", ciphertext)
    # print("digit remove 결과 : ", ciphertext)
    
    # bit ring 생성
    ring = create_ring(q=q, t=2)
    # 복호화
    dec_ciphertext = ring.decrypt(ciphertext)
    print("복호화 결과 : ", dec_ciphertext)