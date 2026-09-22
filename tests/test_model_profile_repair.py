"""Synthetic regression checks for the repaired model-profile module."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
from pathlib import Path
import sys
import unittest

from megalodon import model_profile as m


def fixture(profile_id: str = "synthetic-one") -> dict:
    return {
        "schema": m.PROFILE_SCHEMA,
        "profile_id": profile_id,
        "status": "candidate",
        "evidence_class": "synthetic_fixture",
        "provider": "ollama",
        "endpoint": "http://127.0.0.1:11434",
        "model_alias": "qwen-test:fixture-a",
        "ollama_manifest_digest": "a" * 64,
        "artifact_sha256": "b" * 64,
        "provenance_sha256": "c" * 64,
        "containment_receipt_sha256": "d" * 64,
        "model_family": "qwen-test",
        "quantization": "Q4_K_M",
        "context_window": 8192,
        "operational_context": 4096,
        "purpose": "advisory",
        "structured_output": True,
        "thinking_enabled": False,
        "license": "synthetic-test-only",
        "source_reference": "synthetic-fixture:no-real-artifact",
        "runner": {
            "name": "ollama",
            "version": "fixture-1",
            "binary_sha256": "e" * 64,
        },
        "evaluation": {
            "corpus_sha256": "f" * 64,
            "sample_count": 10,
            "schema_valid_count": 10,
            "citation_valid_count": 10,
            "refusal_valid_count": 10,
            "p95_latency_ms": 100,
            "max_rss_mib": 512,
        },
    }


class RepairTests(unittest.TestCase):
    def refuses(self, code, function, *args):
        with self.assertRaises(m.ModelProfileError) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)

    def test_valid_profile(self):
        raw = fixture()
        validated = m.validate_profile(raw)
        self.assertEqual(validated.value, raw)
        self.assertTrue(validated.hard_gate_passed)
        self.assertEqual(validated.gate_failures, ())

    def test_profile_digest(self):
        raw = fixture()
        self.assertEqual(
            m.validate_profile(raw).canonical_sha256,
            sha256(m.canonical_json(raw).encode("ascii")).hexdigest(),
        )

    def test_boundary_digest(self):
        raw = fixture()
        expected = sha256(
            m.canonical_json(m._comparison_boundary(raw)).encode("ascii")
        ).hexdigest()
        self.assertEqual(m.validate_profile(raw).comparison_boundary_sha256, expected)

    def test_input_snapshot_is_independent(self):
        raw = fixture()
        expected = deepcopy(raw)
        validated = m.validate_profile(raw)
        raw["profile_id"] = "changed-after-validation"
        raw["runner"]["version"] = "changed"
        raw["evaluation"]["sample_count"] = 999
        self.assertEqual(validated.value, expected)

    def test_returned_snapshot_is_independent(self):
        validated = m.validate_profile(fixture())
        view = validated.value
        view["runner"]["version"] = "changed"
        self.assertEqual(validated.value, fixture())
        self.assertIsNot(view, validated.value)

    def test_snapshot_fields_are_frozen(self):
        validated = m.validate_profile(fixture())
        with self.assertRaises(FrozenInstanceError):
            validated.canonical_sha256 = "0" * 64

    def test_synthetic_packet_and_authority(self):
        validated = m.validate_profile(fixture())
        packet = m.binding_candidate_packet(validated)
        self.assertEqual(packet["state"], "SYNTHETIC_ONLY")
        self.assertEqual(packet["remaining_holds"], list(m.SEPARATE_HOLDS))
        self.assertTrue(all(flag is False for flag in packet["authority"].values()))
        self.assertEqual(packet["profile_sha256"], validated.canonical_sha256)
        self.assertEqual(packet["comparison_boundary_sha256"], validated.comparison_boundary_sha256)

    def test_operator_packet_state_not_admission(self):
        raw = fixture()
        # This tests a label, not a real operator observation.
        raw["evidence_class"] = "operator_observed"
        packet = m.binding_candidate_packet(m.validate_profile(raw))
        self.assertEqual(packet["state"], "CANDIDATE_VALIDATED")
        self.assertFalse(packet["authority"]["admits_model"])
        self.assertIn("OWNER_MODEL_BINDING", packet["remaining_holds"])

    def test_incomplete_gates_have_stable_order(self):
        raw = fixture()
        raw["evidence_class"] = "operator_observed"
        for key in ("schema_valid_count", "citation_valid_count", "refusal_valid_count"):
            raw["evaluation"][key] = 9
        validated = m.validate_profile(raw)
        self.assertFalse(validated.hard_gate_passed)
        self.assertEqual(validated.gate_failures, (
            "SCHEMA_VALIDATION_INCOMPLETE",
            "CITATION_VALIDATION_INCOMPLETE",
            "REFUSAL_VALIDATION_INCOMPLETE",
        ))
        self.assertEqual(m.binding_candidate_packet(validated)["state"], "EVALUATION_HOLD")

    def test_canonical_order_and_round_trip(self):
        raw = fixture()
        reversed_raw = dict(reversed(list(raw.items())))
        self.assertEqual(m.canonical_json(raw), m.canonical_json(reversed_raw))
        self.assertEqual(m.parse_profile_bytes(m.canonical_json(raw).encode("ascii")), raw)

    def test_like_for_like_ranking_and_no_selection(self):
        first, second = fixture(), fixture("synthetic-two")
        second["evaluation"]["p95_latency_ms"] = 50
        validated = [m.validate_profile(first), m.validate_profile(second)]
        result = m.compare_profiles(validated)
        self.assertEqual([row["profile_id"] for row in result["ranking"]], ["synthetic-two", "synthetic-one"])
        self.assertIsNone(result["selection"])
        self.assertEqual(result["state"], "COMPARISON_ONLY")
        self.assertEqual(result["comparison_boundary_sha256"], validated[0].comparison_boundary_sha256)
        self.assertEqual(result, m.compare_profiles(list(reversed(validated))))

    def test_hard_gate_precedes_speed(self):
        first, second = fixture(), fixture("synthetic-two")
        second["evaluation"]["p95_latency_ms"] = 1
        second["evaluation"]["citation_valid_count"] = 9
        result = m.compare_profiles([m.validate_profile(first), m.validate_profile(second)])
        self.assertEqual(result["ranking"][0]["profile_id"], "synthetic-one")

    def test_memory_then_id_break_latency_ties(self):
        first, second = fixture(), fixture("synthetic-two")
        second["evaluation"]["max_rss_mib"] = 256
        result = m.compare_profiles([m.validate_profile(first), m.validate_profile(second)])
        self.assertEqual(result["ranking"][0]["profile_id"], "synthetic-two")
        second["evaluation"]["max_rss_mib"] = 512
        result = m.compare_profiles([m.validate_profile(second), m.validate_profile(first)])
        self.assertEqual(result["ranking"][0]["profile_id"], "synthetic-one")

    def test_mixed_boundaries_refused(self):
        changes = (
            (("evidence_class",), "operator_observed"),
            (("purpose",), "explanation"),
            (("operational_context",), 2048),
            (("runner", "version"), "fixture-2"),
            (("runner", "binary_sha256"), "0" * 64),
            (("evaluation", "corpus_sha256"), "1" * 64),
            (("evaluation", "sample_count",), 11),
        )
        for path, value in changes:
            with self.subTest(path=path):
                first, second = fixture(), fixture("synthetic-two")
                target = second
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                self.refuses("COMPARISON_BOUNDARY_MISMATCH", m.compare_profiles,
                             [m.validate_profile(first), m.validate_profile(second)])

    def test_candidate_attributes_may_differ(self):
        first, second = fixture(), fixture("synthetic-two")
        second.update(model_alias="qwen-test:fixture-b", model_family="qwen-other",
                      quantization="Q8_0", context_window=16384,
                      artifact_sha256="0" * 64, ollama_manifest_digest="1" * 64)
        one, two = m.validate_profile(first), m.validate_profile(second)
        self.assertNotEqual(one.canonical_sha256, two.canonical_sha256)
        self.assertEqual(one.comparison_boundary_sha256, two.comparison_boundary_sha256)
        self.assertEqual(len(m.compare_profiles([one, two])["ranking"]), 2)

    def test_duplicate_ids_refused(self):
        validated = m.validate_profile(fixture())
        self.refuses("DUPLICATE_PROFILE_ID", m.compare_profiles, [validated, validated])

    def test_comparison_count_limits(self):
        validated = m.validate_profile(fixture())
        for count in (0, 1, 33):
            with self.subTest(count=count):
                self.refuses("PROFILE_COUNT", m.compare_profiles, [validated] * count)
        result = m.compare_profiles([m.validate_profile(fixture(f"synthetic-{i:02d}")) for i in range(32)])
        self.assertEqual(len(result["ranking"]), 32)

    def test_duplicate_json_keys_refused(self):
        for raw in (b'{"a":1,"a":2}', b'{"outer":{"a":1,"a":2}}'):
            self.refuses("DUPLICATE_JSON_KEY", m.parse_profile_bytes, raw)

    def test_nonfinite_numbers_refused(self):
        for raw in (b'NaN', b'Infinity', b'-Infinity', b'1e9999', b'-1e9999', b'{"x":1e9999}'):
            with self.subTest(raw=raw):
                self.refuses("NON_FINITE_NUMBER", m.parse_profile_bytes, raw)
        self.assertEqual(m.parse_profile_bytes(b'1.5'), 1.5)

    def test_invalid_json_and_utf8_refused(self):
        for raw in (b'{', b'\xff', b'{} {}', b'\xef\xbb\xbf{}', b' '):
            with self.subTest(raw=raw):
                self.refuses("INVALID_JSON", m.parse_profile_bytes, raw)

    def test_large_integer_conversion_error_is_wrapped(self):
        limit = sys.get_int_max_str_digits()
        if limit == 0 or limit + 1 > m.MAX_PROFILE_BYTES:
            self.skipTest("Interpreter integer digit limit disabled or exceeds input bound")
        self.refuses("INVALID_JSON", m.parse_profile_bytes, b'9' * (limit + 1))

    def test_byte_type_and_size_limits(self):
        for raw in (b'', 'not-bytes', bytearray(b'{}'), b' ' * (m.MAX_PROFILE_BYTES + 1)):
            self.refuses("PROFILE_SIZE", m.parse_profile_bytes, raw)
        self.assertEqual(m.parse_profile_bytes(b'{}' + b' ' * (m.MAX_PROFILE_BYTES - 2)), {})

    def test_closed_mapping_shapes(self):
        for value in (None, [], {}, dict(fixture(), extra=True)):
            self.refuses("PROFILE_SHAPE", m.validate_profile, value)
        for key, code in (("runner", "RUNNER_SHAPE"), ("evaluation", "EVALUATION_SHAPE")):
            for invalid in (None, [], {}, {"unexpected": 1}):
                raw = fixture()
                raw[key] = invalid
                self.refuses(code, m.validate_profile, raw)

    def test_unhashable_enums_are_fixed_code_errors(self):
        for field, code in (("purpose", "PURPOSE"), ("evidence_class", "EVIDENCE_CLASS")):
            for invalid in ([], {}, None, 1, True, "invalid"):
                raw = fixture()
                raw[field] = invalid
                self.refuses(code, m.validate_profile, raw)

    def test_numeric_ranges_and_bool_rejection(self):
        for field, code, values in (
            ("context_window", "CONTEXT_WINDOW", [True, 255, 1_048_577, 4096.0]),
            ("operational_context", "OPERATIONAL_CONTEXT", [True, 255, 4097, "4096"]),
        ):
            for value in values:
                raw = fixture()
                raw[field] = value
                self.refuses(code, m.validate_profile, raw)
        for field, code, value in (
            ("sample_count", "SAMPLE_COUNT", 0),
            ("sample_count", "SAMPLE_COUNT", True),
            ("schema_valid_count", "SCHEMA_VALID_COUNT", 11),
            ("citation_valid_count", "CITATION_VALID_COUNT", -1),
            ("refusal_valid_count", "REFUSAL_VALID_COUNT", False),
            ("p95_latency_ms", "P95_LATENCY_MS", 0),
            ("max_rss_mib", "MAX_RSS_MIB", 0),
        ):
            raw = fixture()
            raw["evaluation"][field] = value
            self.refuses(code, m.validate_profile, raw)

    def test_context_relation(self):
        raw = fixture()
        raw["context_window"] = 2048
        self.refuses("CONTEXT_RELATION", m.validate_profile, raw)

    def test_text_hash_and_runtime_constraints(self):
        for field, value, code in (
            ("profile_id", "Bad-ID", "PROFILE_ID"),
            ("schema", "unknown", "SCHEMA_MISMATCH"),
            ("status", "accepted", "STATUS"),
            ("provider", "other", "PROVIDER"),
            ("endpoint", "http://localhost:11434", "ENDPOINT"),
            ("model_alias", "other:tag", "MODEL_ALIAS"),
            ("model_family", "other", "MODEL_FAMILY"),
            ("quantization", "bad/value", "QUANTIZATION"),
            ("artifact_sha256", "A" * 64, "ARTIFACT_SHA256"),
            ("provenance_sha256", "a" * 63, "PROVENANCE_SHA256"),
            ("license", " leading-space", "LICENSE"),
            ("source_reference", "bad\nreference", "SOURCE_REFERENCE"),
            ("source_reference", "bad\u202ereference", "SOURCE_REFERENCE"),
            ("structured_output", 1, "STRUCTURED_OUTPUT_REQUIRED"),
            ("thinking_enabled", 0, "THINKING_MUST_BE_DISABLED"),
            ("purpose", "tool-selection", "PURPOSE"),
        ):
            with self.subTest(field=field, value=value):
                raw = fixture()
                raw[field] = value
                self.refuses(code, m.validate_profile, raw)

    def test_complete_source_has_no_conflict_markers(self):
        text = Path(m.__file__).read_text(encoding="utf-8")
        self.assertFalse(any(line.startswith(("<<<<<<<", "=======", ">>>>>>>")) for line in text.splitlines()))
        self.assertEqual(text.count("    def value(self)"), 1)
        self.assertEqual(text.count("    return ValidatedProfile("), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
