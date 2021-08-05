import binascii
import base58
import sha3

import json

from zenroom import zenroom
# from zenroom.zenroom import ZenroomException

from sha3 import sha3_256
from base64 import b64decode, b64encode

from cryptoconditions.crypto import Ed25519SigningKey as SigningKey

from pyasn1.type import univ
from pyasn1.type.univ import Choice, OctetString, Integer, Sequence
from pyasn1.type.char import UTF8String, IA5String
from pyasn1.type.namedtype import NamedType, NamedTypes
from pyasn1.type.constraint import ValueRangeConstraint, ValueSizeConstraint
from pyasn1.type.tag import (
    Tag, tagClassContext, tagFormatConstructed, tagFormatSimple)


from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.codec.native.encoder import encode as nat_encode
from pyasn1.codec.native.decoder import decode as nat_decode

from cryptoconditions import TypeRegistry
from cryptoconditions import Ed25519Sha256
from cryptoconditions.crypto import base64_add_padding, base64_remove_padding
from cryptoconditions.exceptions import ParsingError, PrefixError
from bigchaindb_driver.crypto import generate_keypair, CryptoKeypair

from cryptoconditions.schemas.condition import Condition as Asn1Condition

import inspect

# This code exemplifies the way to serialize zenroom and zencode scripts inside and outside of chains

# start by defining everything we need for the zenroom contract

did = None
script = "print('Hello world')"
keys = None
data = None
conf = None
verbosity = 0

scrpt_jsn = {
    'did': None,
    'script': "print('Hello world')",
    'keys': None,
    'data': None,
    'verbsoity': 0,
}

# SHA256 scrpt_jsn and sign ist wth master secret. a hardcoded one for demonstration purposes
# JSON: serialize the transaction-without-id zenroom part to a json formatted string
message = json.dumps(
    scrpt_jsn,
    sort_keys=True,
    separators=(',', ':'),
    ensure_ascii=False,
)

message = sha3.sha3_256(message.encode())
print(F'    message:   {message.hexdigest()}')

key_ring = CryptoKeypair(private_key='Bs2h46THPD3ezJ7Giisq5MJbuWo7mpz8GF9NbW1Bspjo', public_key='5bxnttfSNScCL2YtKWXKfya1uMq1TEg9nznX7cnKFiPR')

# CRYPTO-CONDITIONS: instantiate an Ed25519 crypto-condition for buyer
ed25519 = Ed25519Sha256(public_key=base58.b58decode(key_ring.public_key))

ed25519.sign(message.digest(), base58.b58decode(key_ring.private_key))


# in case this gets executed:
# output, errors = zenroom.execute(script)

# turn the zenroom contract into a DID: decentralized identifier

sha3 = sha3_256()
sha3.update(script.encode())
digest = sha3.hexdigest()

digest64 = b64encode(digest.encode())

did = "DID without ASN1 encoding:  did:ipdb:" + digest
print(F'{did}')

did = "DID with Base64 encoding:  did:ipdb:" + str(digest64)
print(F'{did}')

script_str = """
    -- generate a simple keyring
    keyring = ECDH.new()
    keyring:keygen()
    
    -- export the keypair to json
    export = JSON.encode(
       {
          public  = keyring: public():base64(),
          private = keyring: private():base64()
       }
    )
    print(export)
"""

"""
b'MIIBMxaCARoKICAgIC0tIGdlbmVyYXRlIGEgc2ltcGxlIGtleXJpbmcKICAgIGtleXJpbmcgPSBFQ0RILm5ld
ygpCiAgICBrZXlyaW5nOmtleWdlbigpCiAgICAKICAgIC0tIGV4cG9ydCB0aGUga2V5cGFpciB0byBqc29uCiAg
ICBleHBvcnQgPSBKU09OLmVuY29kZSgKICAgICAgIHsKICAgICAgICAgIHB1YmxpYyAgPSBrZXlyaW5nOiBwdWJ
saWMoKTpiYXNlNjQoKSwKICAgICAgICAgIHByaXZhdGUgPSBrZXlyaW5nOnByaXZhdGUoKTpiYXNlNjQoKQogIC
AgICAgfQogICAgKQogICAgcHJpbnQoZXhwb3J0KQoWBE5vbmUWBE5vbmUWBE5vbmUCAQA='
"""


# define ASN1 Scheme for zenroom code

class ZenroomScript(Sequence):
    """
    ASN.1 specification:

    ZenroomScript ::= SEQUENCE {
        script           IA5STRING,  -- n
        keys             IA5STRING,  -- e
        data             IA5STRING,  -- n
        conf             IA5STRING,  -- e
        verbosity        INTEGER,    -- n
    }
    """
    componentType = NamedTypes(
        NamedType('script', IA5String()),
        NamedType('keys',   IA5String()),
        NamedType('data',   IA5String()),
        NamedType('conf',   IA5String()),
        NamedType('verbosity', Integer()),
    )

zenroomScript = ZenroomScript()

# ASN.1 SEQUENCE type quacks like Python dict
zenroomScript['script'] = script_str
zenroomScript['keys'] = None
zenroomScript['data'] = None
zenroomScript['conf'] = None
zenroomScript['verbosity'] = 0

# assert zenroomScript.isValue == False
zenroomScript['script'].isValue = True
zenroomScript['keys'].isValue = True
zenroomScript['data'].isValue = True
zenroomScript['conf'].isValue = True
zenroomScript['verbosity'].isValue = True
zenroom.isValue = True

py_zenroomScript = nat_encode(zenroomScript)
print(py_zenroomScript)

der_serialisation = der_encode(zenroomScript)

b64_serialisation = b64encode(der_serialisation)
print(b64_serialisation)

b64_deserialisation = b64decode(b64_serialisation)
print(b64_deserialisation)

der_deserialisation = der_decode(b64_deserialisation, asn1Spec=zenroomScript)
print(der_deserialisation)
print(der_deserialisation[0])
print(der_deserialisation[1])

zendigest64 = b64encode(digest.encode())

did = "Zen DID with ASN1 encoding:  did:ipdb:" + str(b64_serialisation.decode())
print(F'{did}')