from jwcrypto import jwt,jwe,jws,jwk
from jwcrypto.common import json_encode, json_decode
import json

f = open('/root/tests/data/reg_comp_03_register_data.json')
data = json.load(f)
print("Data")
print(data)

public_key = jwk.JWK()
private_key = jwk.JWK.generate(kty='oct',size=256)
#public_key.import_key(**json_decode(private_key.export_public()))
print()
print("Private Key")
print(vars(private_key))
print()
print("Public Key")
print(vars(public_key))

jwsToken = jws.JWS(str(data).encode('utf-8'))
jwsToken.add_signature(private_key,None,json_encode({"alg":"HS512"}),json_encode({"kid":private_key.thumbprint()}))
signed = jwsToken.serialize()
print()
print("Signed")
print(signed)

protected_header = {
        "alg": "A256KW",
        "enc": "A256CBC-HS512",
        "typ": "JWE",
#        "kid": public_key.thumbprint(),
    }
jweToken = jwe.JWE(signed.encode('utf-8'),json_encode({"alg": "A256KW","enc": "A256CBC-HS512"}))
jweToken.add_recipient(private_key)
enc = jweToken.serialize()
print()
print("Signed and Enrypted")
print(enc)

jweToken = jwe.JWE()
jweToken.deserialize(enc,key=private_key)
jweToken.decrypt(private_key)
sig = jweToken.payload
print()
print("Decrypted Signed")
print(sig)

print()
jwsToken = jws.JWS()
jwsToken.deserialize(sig)
if jwsToken.verify(private_key):
   print("Signature Verified")
else:
   print("Signature Invalid")
payload = jwsToken.payload
print()
print("Decrypted and Deserialized Data")
print(payload)
