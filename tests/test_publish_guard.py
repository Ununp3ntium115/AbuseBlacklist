import unittest

from scripts.publish_guard import MAX_FAILED_SOURCE_RATIO, degraded_reason


def stats(total, ok, high_confidence=1000):
    return {"sources_total": total, "sources_ok": ok, "high_confidence_indicators": high_confidence}


class PublishGuardTests(unittest.TestCase):
    def test_healthy_build_is_publishable(self):
        self.assertIsNone(degraded_reason(stats(64, 63)))

    def test_no_successful_source_is_refused(self):
        self.assertIn("no upstream source", degraded_reason(stats(64, 0)))
        self.assertIn("no upstream source", degraded_reason({}))

    def test_failure_ratio_boundary(self):
        total = 64
        at_limit_ok = total - int(total * MAX_FAILED_SOURCE_RATIO)
        self.assertIsNone(degraded_reason(stats(total, at_limit_ok)))
        self.assertIn("sources failed", degraded_reason(stats(total, at_limit_ok - 1)))

    def test_country_zones_alone_cannot_publish_empty_abuse_feeds(self):
        # 39 IPdeny zones up, all 25 abuse/privacy/context feeds down: under the ratio, but nothing to block.
        self.assertIn("high-confidence", degraded_reason(stats(64, 39, high_confidence=0)))


if __name__ == "__main__":
    unittest.main()
