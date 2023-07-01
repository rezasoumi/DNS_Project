from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json
from Crypto.Cipher import DES3, AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
# pn = dh.DHParameterNumbers(parameters.parameter_numbers().p, parameters.parameter_numbers().g)
# parameters = pn.parameters()

# public_numbers = dh.DHPublicNumbers(public_key_value, parameters.parameter_numbers())
# reconstructed_public_key = public_numbers.public_key()

# public_key_value = alice_public_key.public_numbers().y

# alice_public_key_bytes = alice_public_key.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# )
# bob_public_key_bytes = bob_public_key.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# )


# bob_public_key = serialization.load_pem_public_key(bob_public_key_bytes)
# shared_key_bob = alice_private_key.exchange(bob_public_key)

# assert shared_key_alice == shared_key_bob

# derived_key = HKDF(
#     algorithm=hashes.SHA256(),
#     length=32,
#     salt=None,
#     info=b'session_key',
# ).derive(shared_key_alice)

# json_message = {
#     "name": "John Doe",
#     "age": 30,
#     "city": "New York"
# }
# json_bytes = json.dumps(json_message).encode('utf-8')

# cipher = AES.new(derived_key, AES.MODE_ECB)
# encrypted_data = cipher.encrypt(pad(json_bytes, AES.block_size))

# decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

# decrypted_json = json.loads(decrypted_data.decode('utf-8'))

# with open("session_key.key", "wb") as file:
#     file.write(derived_key)

# with open("session_key.key", "rb") as file:
#     loaded_key = file.read()


parameters = dh.generate_parameters(generator=2, key_size=512)

alice_private_key = parameters.generate_private_key()
alice_public_key = alice_private_key.public_key()

bob_private_key = parameters.generate_private_key()
bob_public_key = bob_private_key.public_key()

reza_private_key = parameters.generate_private_key()
reza_public_key = reza_private_key.public_key()

# print(type(bob_private_key.exchange(alice_public_key)))
# print(int.from_bytes(bob_private_key.exchange(alice_public_key), byteorder='big'))

# public_numbers = dh.DHPublicNumbers(int.from_bytes(bob_private_key.exchange(alice_public_key), byteorder='big'), parameters.parameter_numbers())
# reconstructed_public_key = public_numbers.public_key()
# print(reconstructed_public_key.public_numbers().y)

alice_bob = bob_private_key.exchange(alice_public_key)
reza_alice = alice_private_key.exchange(reza_public_key)

pub_alice_bob = dh.DHPublicNumbers(int.from_bytes(alice_bob, byteorder='big'), parameters.parameter_numbers()).public_key()
pub_reza_alice = dh.DHPublicNumbers(int.from_bytes(reza_alice, byteorder='big'), parameters.parameter_numbers()).public_key()

shared_key_alice_bob_reza = reza_private_key.exchange(pub_alice_bob)

shared_key_reza_alice_bob = bob_private_key.exchange(pub_reza_alice)

assert shared_key_reza_alice_bob == shared_key_alice_bob_reza
