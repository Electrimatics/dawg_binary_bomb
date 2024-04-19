def phase2():
    flag = "Y0u_FoUND_mY_k3y"
    encoded = ''

    for o in [ord(c) for c in flag]:
        # o ^= 0x11
        # o ^= 0x22
        # o ^= 0x33
        o ^= 0x44
        o ^= 0x55

        encoded += chr(o)
    
    print(encoded)

def phase4():
    flag = "Cu7_mY_5Tr1Ng_iN70_PI3c3s"
    encoded = ''

    for o in [ord(c) for c in flag]:
        u = (o & 0xf0) >> 4
        u = (u >> 2) | ((u & 0x3) << 2)

        l = o & 0x0f
        l = (l >> 2) | ((l & 0x3) << 2)
        o = (l << 4) | u
        encoded += f"0x{o:02x}, "

    print(encoded)

def phase5():
    flag = "Ca5c4d1ng_X0R_3nCrYP7i0n"
    encoded = ''

    for i in range(len(flag)-1):
        c = ord(flag[i]) ^ ord(flag[i+1])
        c ^= 0x34

        encoded = f"0x{c:02x}, " + encoded

    c = ord(flag[len(flag)-1]) ^ 0x34
    encoded = f"0x{c:02x}, " + encoded

    print(encoded)

phase2()
phase4()
phase5()
