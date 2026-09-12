import json
import unittest

from air_recommender import (
    MAX_GPT5_COMPLETION_TOKENS,
    MAX_LEGACY_COMPLETION_TOKENS,
    MAX_RESPONSE_BYTES,
    MAX_TIMEOUT_SECONDS,
    OpenAICompatibleClient,
    VerifiedIncidentEvidence,
    build_signing_request,
    encode_signed_recommendation,
    keccak256,
    parse_model_output,
    recommend,
    source_floor,
)


EVIDENCE_ID = "0x" + "11" * 32
INCIDENT_ID = "0x" + "22" * 32
POLICY_HASH = "0x" + "33" * 32
RESPONDER = "0x1234567890123456789012345678901234567890"
R = "0x" + "44" * 32
S = "0x" + "55" * 32
VALID_UNTIL = 2_000_000_000


def evidence(severity=1):
    return VerifiedIncidentEvidence(
        evidence_id=EVIDENCE_ID,
        incident_id=INCIDENT_ID,
        severity=severity,
        source_chain_key="creditcoin-test-source",
        source_contract="0x1234567890123456789012345678901234567890",
        source_block=123456,
        tx_index=7,
    )


def model_json(mode="LIMITED", evidence_id=EVIDENCE_ID, reason="Verified policy breach; restrict treasury spend.", **extra):
    obj = {"evidence_id": evidence_id, "mode": mode, "reason": reason}
    obj.update(extra)
    return json.dumps(obj)


class FakeClient:
    def __init__(self, raw=None, exc=None):
        self.raw = raw
        self.exc = exc

    def complete(self, _evidence):
        if self.exc:
            raise self.exc
        return self.raw


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload
        self.read_sizes = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size=-1):
        self.read_sizes.append(size)
        if size is None or size < 0:
            return self.payload
        return self.payload[:size]


class AirRecommenderTest(unittest.TestCase):
    def test_keccak_matches_ethereum_reference_vectors(self):
        vectors = [
            (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
            (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
            (b"a" * 134, "e5de5653994e2fa6729d329b65b5f332dee942a7ea54515e173824c232a4ff91"),
            (b"a" * 135, "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446"),
            (b"a" * 136, "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e"),
            (b"a" * 270, "cfecd7939f149ad981c5672b3a7c4fe8b584b6b3dbe899b2575c8a92e77f8f28"),
            (b"a" * 271, "132f47effd6c8b1b299efa53fe68aece77ec8ae4eb2e294f668eec94f76001e1"),
            (b"a" * 272, "cf7fcd4f705ee749930d19ca84561a9bf62516bd90a471545fa2f49fdc7e63c8"),
            ("AIR → reserve ⚠️ 💥".encode("utf-8"), "b7cb911503d9ce90b95dff0078e3e8b1273461abeba5cf2655e2859c502b8fd7"),
            (("AIR → reserve ⚠️ 💥" * 20).encode("utf-8"), "25888a09ac40030d6dfb5889a6c667c3a2cad23056b34e94d88caf206185d54c"),
        ]
        for payload, expected in vectors:
            with self.subTest(length=len(payload)):
                self.assertEqual(keccak256(payload).hex(), expected)

    def test_valid_warning_creates_non_authoritative_intent(self):
        result = parse_model_output(evidence(1), model_json())
        self.assertFalse(result.fallback)
        self.assertEqual(result.mode, "LIMITED")
        self.assertEqual(result.evidence_id, EVIDENCE_ID)
        self.assertEqual(result.rationale_hash, "0x" + keccak256(result.reason.encode()).hex())
        self.assertFalse(hasattr(result, "payload_hex"))

    def test_signing_request_exactly_binds_domain_policy_evidence_mode_rationale_and_expiry(self):
        intent = parse_model_output(evidence(1), model_json(mode="FROZEN"))
        request = build_signing_request(intent, POLICY_HASH, 102031, RESPONDER, VALID_UNTIL)
        self.assertEqual(request["primaryType"], "AIRRecommendation")
        self.assertEqual(request["domain"], {
            "name": "AIR", "version": "1", "chainId": 102031, "verifyingContract": RESPONDER,
        })
        self.assertEqual(request["message"], {
            "policyHash": POLICY_HASH,
            "fingerprint": EVIDENCE_ID,
            "mode": 2,
            "rationaleHash": intent.rationale_hash,
            "validUntil": VALID_UNTIL,
        })
        self.assertEqual(
            request["types"]["AIRRecommendation"],
            [
                {"name": "policyHash", "type": "bytes32"},
                {"name": "fingerprint", "type": "bytes32"},
                {"name": "mode", "type": "uint8"},
                {"name": "rationaleHash", "type": "bytes32"},
                {"name": "validUntil", "type": "uint64"},
            ],
        )

    def test_signed_envelope_encodes_exact_224_byte_solidity_tuple(self):
        intent = parse_model_output(evidence(1), model_json(mode="FROZEN"))
        raw = bytes.fromhex(encode_signed_recommendation(intent, VALID_UNTIL, R, S, 27)[2:])
        self.assertEqual(len(raw), 224)
        words = [raw[i : i + 32] for i in range(0, len(raw), 32)]
        self.assertEqual(words[0], bytes.fromhex(EVIDENCE_ID[2:]))
        self.assertEqual(int.from_bytes(words[1], "big"), 2)
        self.assertEqual(words[2], bytes.fromhex(intent.rationale_hash[2:]))
        self.assertEqual(int.from_bytes(words[3], "big"), VALID_UNTIL)
        self.assertEqual(words[4], bytes.fromhex(R[2:]))
        self.assertEqual(words[5], bytes.fromhex(S[2:]))
        self.assertEqual(int.from_bytes(words[6], "big"), 27)

    def test_fallback_intent_cannot_be_signed_or_encoded(self):
        fallback = parse_model_output(evidence(1), "not-json")
        self.assertTrue(fallback.fallback)
        self.assertEqual(fallback.mode, "LIMITED")
        self.assertEqual(fallback.cause, "invalid_output")
        with self.assertRaisesRegex(ValueError, "must not be signed"):
            build_signing_request(fallback, POLICY_HASH, 102031, RESPONDER, VALID_UNTIL)
        with self.assertRaisesRegex(ValueError, "must not be encoded"):
            encode_signed_recommendation(fallback, VALID_UNTIL, R, S, 27)

    def test_signed_envelope_rejects_invalid_signature_shape_and_expiry_width(self):
        intent = parse_model_output(evidence(1), model_json())
        for kwargs in (
            {"valid_until": 1 << 64, "r": R, "s": S, "v": 27},
            {"valid_until": VALID_UNTIL, "r": "0x" + "00" * 32, "s": S, "v": 27},
            {"valid_until": VALID_UNTIL, "r": R, "s": "0x" + "00" * 32, "v": 27},
            {"valid_until": VALID_UNTIL, "r": R, "s": S, "v": 29},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                encode_signed_recommendation(intent, **kwargs)

    def test_warning_may_propose_frozen_but_cannot_add_authority(self):
        strengthened = parse_model_output(evidence(1), model_json(mode="FROZEN"))
        self.assertFalse(strengthened.fallback)
        self.assertEqual(strengthened.mode, "FROZEN")

        injected = parse_model_output(evidence(1), model_json(beneficiary="0xdead"))
        self.assertTrue(injected.fallback)
        self.assertEqual(injected.mode, "LIMITED")

    def test_critical_can_only_be_frozen(self):
        weak = parse_model_output(evidence(2), model_json(mode="LIMITED"))
        self.assertTrue(weak.fallback)
        self.assertEqual(weak.mode, "FROZEN")
        strong = parse_model_output(evidence(2), model_json(mode="FROZEN"))
        self.assertFalse(strong.fallback)

    def test_normal_is_never_authorized_for_incident(self):
        result = parse_model_output(evidence(1), model_json(mode="NORMAL"))
        self.assertTrue(result.fallback)
        self.assertEqual(result.mode, "LIMITED")

    def test_source_floor_is_objective_and_severity_derived(self):
        self.assertEqual(source_floor(evidence(1)), "LIMITED")
        self.assertEqual(source_floor(evidence(2)), "FROZEN")

    def test_wrong_evidence_binding_falls_back_to_objective_floor(self):
        result = parse_model_output(evidence(), model_json(evidence_id="0x" + "99" * 32))
        self.assertTrue(result.fallback)
        self.assertIn("binding mismatch", result.reason)
        self.assertEqual(result.mode, "LIMITED")

    def test_malformed_missing_and_oversized_reason_fall_back_to_objective_floor(self):
        for raw in (
            "not-json",
            json.dumps({"evidence_id": EVIDENCE_ID, "mode": "LIMITED"}),
            model_json(reason="x" * 281),
            model_json(reason="   "),
        ):
            with self.subTest(raw=raw[:30]):
                result = parse_model_output(evidence(), raw)
                self.assertTrue(result.fallback)
                self.assertEqual(result.mode, "LIMITED")

    def test_provider_failure_cannot_block_containment_or_escalate_warning(self):
        result = recommend(evidence(), FakeClient(exc=TimeoutError("slow model")))
        self.assertTrue(result.fallback)
        self.assertEqual(result.mode, "LIMITED")
        self.assertEqual(result.cause, "provider_timeout")

    def test_openai_compatible_client_sends_only_bounded_evidence_and_schema(self):
        captured = {}
        content = model_json()
        payload = json.dumps({"choices": [{"message": {"content": content}, "finish_reason": "stop"}]}).encode()
        response = FakeResponse(payload)

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["timeout"] = timeout
            captured["headers"] = dict(request.header_items())
            captured["body"] = json.loads(request.data.decode())
            return response

        client = OpenAICompatibleClient(
            "https://model.invalid/v1",
            "secret",
            "gpt-5-mini",
            timeout_seconds=3.5,
            urlopen=fake_urlopen,
        )
        self.assertEqual(client.complete(evidence()), content)
        self.assertEqual(captured["url"], "https://model.invalid/v1/chat/completions")
        self.assertEqual(captured["timeout"], 3.5)
        self.assertNotIn("temperature", captured["body"])
        self.assertNotIn("max_tokens", captured["body"])
        self.assertEqual(captured["body"]["max_completion_tokens"], MAX_GPT5_COMPLETION_TOKENS)
        self.assertEqual(captured["body"]["reasoning_effort"], "low")
        self.assertEqual(captured["body"]["response_format"], {"type": "json_object"})
        self.assertEqual(response.read_sizes, [MAX_RESPONSE_BYTES + 1])
        user = json.loads(captured["body"]["messages"][1]["content"])
        self.assertEqual(user["verified_evidence"]["policy_floor"], "LIMITED")
        self.assertEqual(user["verified_evidence"]["provenance"], "source_tx_fields_bound_by_on_chain_fingerprint")
        self.assertEqual(user["supplemental_context"]["observation"], "raise")
        self.assertEqual(user["supplemental_context"]["provenance"], "operator_supplied_not_in_fingerprint")
        self.assertNotIn("beneficiary", user)
        self.assertNotIn("calldata", user)
        self.assertNotIn("limit", user)

    def test_legacy_chat_models_still_send_temperature_zero(self):
        captured = {}
        content = model_json()
        payload = json.dumps({"choices": [{"message": {"content": content}, "finish_reason": "stop"}]}).encode()

        def fake_urlopen(request, timeout):
            captured["body"] = json.loads(request.data.decode())
            return FakeResponse(payload)

        client = OpenAICompatibleClient(
            "https://model.invalid/v1",
            "secret",
            "bounded-model",
            timeout_seconds=3.5,
            urlopen=fake_urlopen,
        )
        self.assertEqual(client.complete(evidence()), content)
        self.assertEqual(captured["body"]["temperature"], 0)
        self.assertEqual(captured["body"]["max_tokens"], MAX_LEGACY_COMPLETION_TOKENS)
        self.assertNotIn("max_completion_tokens", captured["body"])

    def test_gemini_chat_models_omit_temperature_and_openai_reasoning_effort(self):
        captured = {}
        content = model_json()
        payload = json.dumps({"choices": [{"message": {"content": content}, "finish_reason": "stop"}]}).encode()

        def fake_urlopen(request, timeout):
            captured["body"] = json.loads(request.data.decode())
            return FakeResponse(payload)

        client = OpenAICompatibleClient(
            "https://generativelanguage.googleapis.com/v1beta/openai",
            "secret",
            "gemini-3.8-flash",
            timeout_seconds=3.5,
            urlopen=fake_urlopen,
        )
        self.assertEqual(client.complete(evidence()), content)
        self.assertNotIn("temperature", captured["body"])
        self.assertNotIn("max_tokens", captured["body"])
        self.assertNotIn("reasoning_effort", captured["body"])
        self.assertEqual(captured["body"]["max_completion_tokens"], MAX_GPT5_COMPLETION_TOKENS)

    def test_openai_compatible_client_rejects_unbounded_timeout_values(self):
        for timeout in (-1.0, 0.0, float("inf"), float("nan"), MAX_TIMEOUT_SECONDS + 0.001):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                OpenAICompatibleClient(
                    "https://model.invalid/v1",
                    "secret",
                    "bounded-model",
                    timeout_seconds=timeout,
                )

    def test_openai_compatible_client_rejects_oversized_response_after_bounded_read(self):
        response = FakeResponse(b"x" * (MAX_RESPONSE_BYTES + 1))

        def fake_urlopen(_request, timeout):
            self.assertEqual(timeout, 1.0)
            return response

        client = OpenAICompatibleClient(
            "https://model.invalid/v1",
            "secret",
            "bounded-model",
            timeout_seconds=1.0,
            urlopen=fake_urlopen,
        )
        with self.assertRaisesRegex(ValueError, "bounded byte limit"):
            client.complete(evidence())
        self.assertEqual(response.read_sizes, [MAX_RESPONSE_BYTES + 1])

    def test_truncated_gpt5_output_is_a_distinct_fallback(self):
        payload = json.dumps({"choices": [{"message": {"content": "{"}, "finish_reason": "length"}]}).encode()

        def fake_urlopen(_request, timeout):
            return FakeResponse(payload)

        client = OpenAICompatibleClient(
            "https://model.invalid/v1",
            "secret",
            "gpt-5-mini",
            timeout_seconds=3.5,
            urlopen=fake_urlopen,
        )
        result = recommend(evidence(), client)
        self.assertTrue(result.fallback)
        self.assertEqual(result.cause, "truncated_output")
        self.assertEqual(result.mode, "LIMITED")

    def test_supplemental_balance_context_is_validated_and_labeled(self):
        with self.assertRaisesRegex(ValueError, "warning_floor"):
            VerifiedIncidentEvidence(
                evidence_id=EVIDENCE_ID,
                incident_id=INCIDENT_ID,
                severity=1,
                source_chain_key="sepolia",
                source_contract=RESPONDER,
                source_block=1,
                tx_index=0,
                warning_floor=100,
                critical_floor=100,
            ).validate()
        captured = {}
        content = model_json()
        payload = json.dumps({"choices": [{"message": {"content": content}, "finish_reason": "stop"}]}).encode()

        def fake_urlopen(request, timeout):
            captured["body"] = json.loads(request.data.decode())
            return FakeResponse(payload)

        thin_ev = VerifiedIncidentEvidence(
            evidence_id=EVIDENCE_ID,
            incident_id=INCIDENT_ID,
            severity=1,
            source_chain_key="sepolia",
            source_contract=RESPONDER,
            source_block=1,
            tx_index=0,
            observation="escalate",
            protected_balance=110,
            warning_floor=200,
            critical_floor=100,
        )
        roomy = VerifiedIncidentEvidence(
            evidence_id=EVIDENCE_ID,
            incident_id=INCIDENT_ID,
            severity=1,
            source_chain_key="sepolia",
            source_contract=RESPONDER,
            source_block=1,
            tx_index=0,
            observation="raise",
            protected_balance=190,
            warning_floor=200,
            critical_floor=100,
        )
        client = OpenAICompatibleClient(
            "https://model.invalid/v1", "secret", "gpt-5-mini", timeout_seconds=3.5, urlopen=fake_urlopen
        )
        client.complete(thin_ev)
        thin_ctx = json.loads(captured["body"]["messages"][1]["content"])["supplemental_context"]
        self.assertEqual(thin_ctx["buffer_to_critical"], 10)
        self.assertEqual(thin_ctx["provenance"], "operator_supplied_not_in_fingerprint")
        client.complete(roomy)
        roomy_ctx = json.loads(captured["body"]["messages"][1]["content"])["supplemental_context"]
        self.assertEqual(roomy_ctx["buffer_to_critical"], 90)
        self.assertNotEqual(thin_ctx["buffer_to_critical"], roomy_ctx["buffer_to_critical"])


if __name__ == "__main__":
    unittest.main()
