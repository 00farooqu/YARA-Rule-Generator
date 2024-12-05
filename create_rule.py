import re
from yara import compile


def extract_strings(file_path):
    """
    Extract printable strings from a binary file.

    :param file_path: Path to the binary file.
    :return: A list of strings extracted from the file.
    """
    strings = []
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                strings.extend(re.findall(b"[ -~]{4,}", chunk))
    except Exception as e:
        print(f"Error reading file: {e}")
    return strings


def sanitize_string(s):
    """
    Sanitize a string for use in YARA rules.
    
    :param s: The raw byte string.
    :return: A sanitized string safe for YARA rules.
    """
    try:
        return s.decode('utf-8', errors='ignore').replace('"', '\\"')
    except Exception as e:
        print(f"Error sanitizing string: {e}")
        return ""


def generate_yara_rule(strings, rule_name):
    """
    Generate a YARA rule based on extracted strings.

    :param strings: List of strings extracted from the binary file.
    :param rule_name: Name for the YARA rule.
    :return: A YARA rule string.
    """
    # Limit to the first 10 sanitized strings
    sanitized_strings = [sanitize_string(s) for s in strings[:10]]
    condition = " or ".join(f'"{s}"' for s in sanitized_strings if s)
    yara_strings = "".join(
        [f'$str{i} = "{s}"\n        ' for i, s in enumerate(sanitized_strings) if s]
    )

    rule = f"""
rule {rule_name} {{
    strings:
        {yara_strings}
    condition:
        {condition}
}}
"""
    return rule


def test_yara_rule(rule, file_path):
    """
    Test a YARA rule against a binary file.

    :param rule: The YARA rule string.
    :param file_path: Path to the binary file to test against.
    :return: List of matches.
    """
    try:
        rule_obj = compile(source=rule)
        matches = rule_obj.match(filepath=file_path)
        return matches
    except Exception as e:
        print(f"Error testing YARA rule: {e}")
        return []


# Main execution
if __name__ == "__main__":
    sample_path = "malware_sample.exe"
    rule_name = "MalwareRule"

    # Step 1: Extract strings from the binary file
    strings = extract_strings(sample_path)

    if not strings:
        print("No strings extracted. Exiting...")
    else:
        # Step 2: Generate a YARA rule
        rule = generate_yara_rule(strings, rule_name)
        print("Generated YARA Rule:")
        print(rule)

        # Step 3: Test the rule against the file
        matches = test_yara_rule(rule, sample_path)
        print(f"YARA Rule Matches: {matches}")
