SECRET_RATE = 0.15

def apply_discount(price, tier):
    if tier >= 3:
        return round(price * (1 - SECRET_RATE * 2), 2)
    if tier == 2:
        return round(price * (1 - SECRET_RATE), 2)
    return price

def validate(key):
    return len(key) == 16 and sum(map(ord, key)) % 97 == 42

if __name__ == "__main__":
    import sys
    print(apply_discount(100.0, 3))
    if len(sys.argv) > 1:
        print("ok" if validate(sys.argv[1]) else "bad")
