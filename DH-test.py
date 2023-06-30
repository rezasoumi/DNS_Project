from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json
from Crypto.Cipher import DES3, AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

parameters = dh.generate_parameters(generator=2, key_size=2048)
pn = dh.DHParameterNumbers(parameters.parameter_numbers().p, parameters.parameter_numbers().g)
parameters = pn.parameters()

alice_private_key = parameters.generate_private_key()
alice_public_key = alice_private_key.public_key()

public_key_value = alice_public_key.public_numbers().y
public_numbers = dh.DHPublicNumbers(public_key_value, parameters.parameter_numbers())
reconstructed_public_key = public_numbers.public_key()

bob_private_key = parameters.generate_private_key()
bob_public_key = bob_private_key.public_key()

alice_public_key_bytes = alice_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

alice_public_key = serialization.load_pem_public_key(alice_public_key_bytes)
shared_key_alice = bob_private_key.exchange(alice_public_key)

bob_public_key_bytes = bob_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

bob_public_key = serialization.load_pem_public_key(bob_public_key_bytes)
shared_key_bob = alice_private_key.exchange(bob_public_key)

assert shared_key_alice == shared_key_bob

derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'session_key',
).derive(shared_key_alice)

json_message = {
    "name": "John Doe",
    "age": 30,
    "city": "New York"
}
json_bytes = json.dumps(json_message).encode('utf-8')

cipher = AES.new(derived_key, AES.MODE_ECB)
encrypted_data = cipher.encrypt(pad(json_bytes, AES.block_size))

decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

decrypted_json = json.loads(decrypted_data.decode('utf-8'))

with open("session_key.key", "wb") as file:
    file.write(derived_key)

with open("session_key.key", "rb") as file:
    loaded_key = file.read()

assert loaded_key == derived_key
