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

phase4()
