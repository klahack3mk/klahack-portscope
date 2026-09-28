# ci_runner.py | Author: klahack | MIT License
"""Run unittest discovery and expose complete failures as GitHub annotations."""

import sys
import unittest


def annotation_escape(value: str) -> str:
    """Escape text for the GitHub Actions workflow-command protocol."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main() -> int:
    """Run the loopback-only suite and annotate each failure or error."""
    sys.path.insert(0, ".")
    suite = unittest.defaultTestLoader.discover("tests", pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    problems = [("Test failure", item) for item in result.failures]
    problems.extend(("Test error", item) for item in result.errors)
    for title, (test, traceback) in problems:
        message = "%s\n%s" % (test.id(), traceback)
        print(
            "::error file=tests/test_klahack_portscope.py,title=%s::%s"
            % (annotation_escape(title), annotation_escape(message))
        )
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
