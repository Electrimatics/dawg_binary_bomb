with open('bbomb', 'r+b') as binary:
    start = int('154c', 16)
    end = int('1611', 16)

    print("Modifying %x to %x" %(start, end))
    binary.seek(start)
    to_modify = binary.read(end-start)
    key = b'\xff'*len(to_modify)
    modified = bytes([_a ^ _b for _a, _b in zip(to_modify, key)])
    print(to_modify)
    print(modified)
    binary.seek(start)
    #binary.write(b'\xFF')
    binary.write(modified)