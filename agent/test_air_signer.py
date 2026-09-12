import json
import unittest

from air_recommender import parse_model_output
from air_signer import address_from_private_key, recover_signer, sign_intent
from test_air_recommender import POLICY_HASH, RESPONDER, VALID_UNTIL, evidence, model_json

KEY = "0x" + "00" * 29 + "0a11ce"


class AirSignerTest(unittest.TestCase):
    def test_signed_payload_recovers_the_recommender_key(self):
        intent = parse_model_output(evidence(1), model_json(mode="FROZEN"))
        signed = sign_intent(intent, POLICY_HASH, 102031, RESPONDER, VALID_UNTIL, KEY)
        signer = address_from_private_key(KEY)
        self.assertEqual(signed["signer"], signer)
        digest = bytes.fromhex(signed["digest"][2:])
        self.assertEqual(recover_signer(digest, signed["r"], signed["s"], signed["v"]), signer)
        self.assertEqual(len(bytes.fromhex(signed["payload"][2:])), 224)
        self.assertLessEqual(int(signed["s"][2:], 16), 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)

    def test_fallback_intent_is_not_signed(self):
        intent = parse_model_output(evidence(1), "not-json")
        with self.assertRaisesRegex(ValueError, "must not be signed"):
            sign_intent(intent, POLICY_HASH, 102031, RESPONDER, VALID_UNTIL, KEY)
