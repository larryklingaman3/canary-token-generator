import secrets

def generate_token_id() -> str:
    return secrets.token_urlsafe(16)  # ~22 chars, base64-url encoded

TRANSPARENT_PIXEL = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000a49444154789c6360000002000155a24f5e0000000049454e44ae426082"
)