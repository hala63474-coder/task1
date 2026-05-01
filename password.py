import hashlib


SPECIAL_CHARS = "!@#$%^&*_-"
WEAK_JWT_VALUES = ["admin", "123456", "password", "secret", "jwtsecret"]



def has_uppercase(text):
    return any(c.isupper() for c in text)

def has_lowercase(text):
    return any(c.islower() for c in text)

def has_digit(text):
    return any(c.isdigit() for c in text)

def has_special(text):
    return any(c in SPECIAL_CHARS for c in text)

def generate_sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()



def password_strength_level(password):
    score = 0

    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if has_uppercase(password):
        score += 1
    if has_lowercase(password):
        score += 1
    if has_digit(password):
        score += 1
    if has_special(password):
        score += 1

    if score <= 2:
        return "Weak"
    elif score == 3:
        return "Medium"
    elif score in [4, 5]:
        return "Strong"
    else:
        return "Very Strong"



def check_password(password):
    print("\n" + "=" * 50)
    print("🔐  PASSWORD CHECK")
    print("=" * 50)

    reasons = []

    if len(password) < 8:
        reasons.append("❌ Too short — minimum 8 characters")
    if not has_uppercase(password):
        reasons.append("❌ Missing uppercase letter (A-Z)")
    if not has_lowercase(password):
        reasons.append("❌ Missing lowercase letter (a-z)")
    if not has_digit(password):
        reasons.append("❌ Missing a number (0-9)")
    if not has_special(password):
        reasons.append(f"❌ Missing special character ({SPECIAL_CHARS})")

    level = password_strength_level(password)

    if reasons:
        print("⚠️  Password is WEAK")
        print(f"📊 Strength Level: {level}")
        print("\nReasons:")
        for r in reasons:
            print(f"   {r}")
    else:
        hash_value = generate_sha256(password)
        print("✅  Password is STRONG")
        print(f"📊 Strength Level: {level}")
        print(f"\n🔑 SHA-256 Hash:\n   {hash_value}")



def check_jwt_secret(secret):
    print("\n" + "=" * 50)
    print("🛡️   JWT SECRET CHECK")
    print("=" * 50)

    reasons = []

    if secret.lower() in WEAK_JWT_VALUES:
        reasons.append("❌ This is a common weak value — never use it!")

    if len(secret) < 16:
        reasons.append("❌ Too short — minimum 16 characters")
    if not has_uppercase(secret):
        reasons.append("❌ Missing uppercase letter (A-Z)")
    if not has_lowercase(secret):
        reasons.append("❌ Missing lowercase letter (a-z)")
    if not has_digit(secret):
        reasons.append("❌ Missing a number (0-9)")
    if not has_special(secret):
        reasons.append(f"❌ Missing special character ({SPECIAL_CHARS})")

    if reasons:
        print("⚠️  JWT Secret is WEAK")
        print("\nReasons:")
        for r in reasons:
            print(f"   {r}")
    else:
        print("✅  JWT Secret is STRONG")


def main():
    print("\n" + "=" * 50)
    print("   🔒 SECURITY CHECKER — M.Training Academy")
    print("=" * 50)

    # --- Password ---
    password = input("\nEnter Password: ")
    check_password(password)

    # --- JWT Secret ---
    print()
    jwt_secret = input("Enter JWT Secret: ")
    check_jwt_secret(jwt_secret)

    print("\n" + "=" * 50)
    print("✔️  Check complete!")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    main()