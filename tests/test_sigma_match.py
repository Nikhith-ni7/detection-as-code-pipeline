import unittest

from sigma_match import compile_rule, logsource_filter, windash_variants


def rule(detection):
    return compile_rule({"detection": detection})


class ModifierTests(unittest.TestCase):
    def test_case_insensitive_contains(self):
        match = rule({"sel": {"CommandLine|contains": "Delete Shadows"}, "condition": "sel"})
        self.assertTrue(match({"CommandLine": "vssadmin DELETE SHADOWS /all"}))

    def test_endswith_value_ending_in_backslash(self):
        match = rule({"sel": {"Path|contains": "\\AppData\\"}, "condition": "sel"})
        self.assertTrue(match({"Path": "C:\\Users\\a\\AppData\\Roaming\\x.exe"}))
        self.assertFalse(match({"Path": "C:\\AppDataBackup"}))

    def test_windash_expands_slash_and_dash(self):
        self.assertIn(" /add", windash_variants(" -add"))
        match = rule({"sel": {"CommandLine|windash|contains": " -add"}, "condition": "sel"})
        self.assertTrue(match({"CommandLine": "net user x /add"}))
        self.assertTrue(match({"CommandLine": "net user x \u2013add"}))

    def test_all_modifier(self):
        match = rule({"sel": {"CommandLine|contains|all": ["a", "b"]}, "condition": "sel"})
        self.assertTrue(match({"CommandLine": "ab"}))
        self.assertFalse(match({"CommandLine": "a"}))

    def test_missing_field_never_matches(self):
        match = rule({"sel": {"Image|endswith": "x.exe"}, "condition": "sel"})
        self.assertFalse(match({}))

    def test_numbers_compare_as_text(self):
        match = rule({"sel": {"EventID": 4769}, "condition": "sel"})
        self.assertTrue(match({"EventID": "4769"}))

    def test_unsupported_modifier_fails(self):
        with self.assertRaises(ValueError):
            rule({"sel": {"CommandLine|re": ".*"}, "condition": "sel"})


class ConditionTests(unittest.TestCase):
    def setUp(self):
        self.detection = {
            "selection_a": {"F": "a"},
            "selection_b": {"G": "b"},
            "filter": {"H": "h"},
        }

    def check(self, condition, event):
        return rule({**self.detection, "condition": condition})(event)

    def test_all_of_and_not(self):
        cond = "all of selection_* and not filter"
        self.assertTrue(self.check(cond, {"F": "a", "G": "b"}))
        self.assertFalse(self.check(cond, {"F": "a", "G": "b", "H": "h"}))
        self.assertFalse(self.check(cond, {"F": "a"}))

    def test_one_of_and_parentheses(self):
        cond = "(1 of selection_*) and not filter"
        self.assertTrue(self.check(cond, {"G": "b"}))
        self.assertFalse(self.check(cond, {"G": "b", "H": "h"}))

    def test_list_of_maps_is_or(self):
        match = rule({"sel": [{"A": "1"}, {"B": "2"}], "condition": "sel"})
        self.assertTrue(match({"B": "2"}))
        self.assertFalse(match({"C": "3"}))

    def test_unknown_selection_fails(self):
        with self.assertRaises(ValueError):
            self.check("missing", {})


class LogsourceTests(unittest.TestCase):
    def test_process_creation_is_sysmon_event_1(self):
        applies = logsource_filter({"category": "process_creation", "product": "windows"})
        self.assertTrue(applies({"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}))
        self.assertFalse(applies({"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 3}))


if __name__ == "__main__":
    unittest.main()
