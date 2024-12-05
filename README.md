# YARA Rule Generator

This script is designed to extract printable strings from binary files and generate YARA rules to help analyse potential malware or suspicious files. It also provides functionality to test the generated YARA rule against the binary file to identify matches.

## Features

- Extracts printable ASCII strings (minimum of 4 characters) from a binary file.
- Generates a YARA rule based on the extracted strings.
- Sanitizes strings to ensure compatibility with YARA.
- Tests the generated rule against the input file for matches.
- Memory-efficient handling of large files by processing in chunks.

---

## Prerequisites

- Python 3.7+
- YARA installed on your system.

---

## Installation

### Step 1: Install YARA

#### macOS (using Homebrew):
```bash
brew install yara
```
#### Linux (using apt):
```bash
sudo apt update
sudo apt install yara
```
#### Windows:
Download and install YARA from the [Official YARA repository](https://github.com/VirusTotal/yara).

Verify YARA installation:
```bash
yara --version
```

#### Step 2: Clone the Repository

Clone the repository to your local machine:
```bash
git clone https://github.com/00farooqu/yara-rule-generator.git
cd yara-rule-generator
```

#### Step 3: Install Python Dependencies
Install the required Python dependencies:
```bash
pip install -r requirements.txt
```

#### Usage

#### 1. Extract Strings and Generate YARA Rule

Run the script with a binary file to extract strings and generate a YARA rule:
```bash
python create_rule.py
```
Modify the sample_path variable in create_rule.py to the path of your binary file (e.g., malware_sample.exe).

#### 2. Test the Generated Rule

The script automatically tests the generated rule against the binary file and outputs any matches:
```bash
Generated YARA Rule:
rule MalwareRule {
    strings:
        $str0 = "example_string_1"
        $str1 = "example_string_2"
    condition:
        "example_string_1" or "example_string_2"
}

YARA Rule Matches: []
```

#### Customisation

- Adjusting the Number of Strings
The script uses the first 10 extracted strings by default. To change this, modify the limit in the generate_yara_rule function.
- Unicode Support
Update the regular expression in extract_strings to handle Unicode if needed:
```bash
re.findall(rb"[\x20-\x7E\x80-\xFF]{4,}", chunk)
```

#### Troubleshooting

If you encounter errors related to the libyara.so file:
1. Ensure libyara.so is installed and available in the correct library path.
2. Set the DYLD_LIBRARY_PATH environment variable on macOS:
```bash
export DYLD_LIBRARY_PATH=/path/to/libyara.so:$DYLD_LIBRARY_PATH
```
#### Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

#### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

#### Disclaimer

This tool is intended for educational and research purposes only. Use it responsibly and ensure you comply with local laws and regulations.
