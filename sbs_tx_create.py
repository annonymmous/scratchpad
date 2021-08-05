import binascii
import base58
import json

from bigchaindb_driver import BigchainDB
from bigchaindb_driver.offchain import prepare_transaction
from bigchaindb_driver.crypto import generate_keypair, CryptoKeypair

from cryptoconditions.crypto import Ed25519SigningKey as SigningKey

# create wallets for all involved parties

# producer
# buyer
# reseller

producer, buyer, reseller = generate_keypair(), generate_keypair(), generate_keypair()

# create certificate

asset = {
    'data': {
        "Certificate": {
        "A03": "0000001",
        "A01": {
            "CompanyName": "voestalpine Krems GmbH",
            "AddressLine": "Schmidhüttenstrasse 5",
            "ZipCode": "3500",
            "City": "Krems",
            "Country": "AT",
            "VAT_Id": "U36909609"
        },
        "B01": "EN10025",
        "B02": "S275J2H",
        "B07": "175508",
        "B13": "24000",
        "C71": "0.1500",
        "C72": "0.0050",
        "C73": "1.0000",
        "C74": "0.0018",
        "C75": "0.2086",
        "C76": "0.0389",
        "C77": "0.0122",
        "C78": "0.0226",
        "C79": "0.0081",
        "C80": "0.0029",
        "C81": "0.0403",
        "C82": "0.0031",
        "C83": "0.0024",
        "C86": "0.017",
        "C93": "0.3361",
        "Z02": "2019-05-30T09:30:10-01:00"
        }
    }
}

metadata = {
    'units': 300,
    'type': 'KG'
}

operation = 'CREATE'

version = '2.0'

input_ = {
    'fulfillment': {
        'public_key': producer.public_key,
        'signature': None,
        'type': 'ed25519-sha-256'
    },
    'fulfills': None,
    'owners_before': (producer.public_key,)
}
inputs = (input_,)

output = {
    'amount': '3000',
    'condition': {
        'details': {
            'type': ed25519.TYPE_NAME,
            'public_key': producer.public_key,
        },
        'uri': ed25519.condition_uri,
    },
    'public_keys': (producer.public_key,),
}
outputs = (outputs,)

creation_tx = {
    'asset': asset,
    'metadata': metadata,
    'operation': operation,
    'outputs': outputs,
    'inputs': inputs,
    'version': version,
    'id': None,
}