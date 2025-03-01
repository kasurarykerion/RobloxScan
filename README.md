# 🚀 RobloxScan

A modern security scanner for Roblox Lua scripts that detects common vulnerabilities and provides fix recommendations.

## ✨ Features

- 🔍 Detects common security vulnerabilities in Roblox scripts
- 🎨 Modern, animated GUI interface with Montserrat font
- 📝 Detailed security reports with recommendations
- 💾 Export reports as text files
- ⚡ Real-time scanning with progress indication

## 🔍 What It Detects

- **RemoteEvent Abuse**: Identifies unsecured RemoteEvent calls that could be exploited
- **Global Variable Exposure**: Detects exposed global variables that could be modified
- **Potential Backdoors**: Finds dangerous functions like loadstring() and getfenv()
- **Unsecured HTTP Requests**: Identifies HTTP requests without proper validation
- **And more...**

## 🛠️ Installation

1. Make sure you have Python 3.7+ installed
2. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/RobloxScan.git
   cd RobloxScan
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 🎮 Usage

1. Run the scanner:
   ```bash
   python main.py
   ```
2. Click "Browse" to select a Lua script
3. Click "Start Scan" to begin analysis
4. View results in the text area
5. Select a vulnerability to see detailed explanation and fix recommendations
6. Save the report using "Save Report" button

## 📁 Example Scripts

The `examples` directory contains:
- `safe_script.lua`: Example of secure coding practices
- `exploit_script.lua`: Example with common vulnerabilities

## 📋 Report Format

Reports include:
- Scan date and time
- File scanned
- List of detected vulnerabilities with line numbers
- Detailed explanations and fix recommendations

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- CustomTkinter for the modern UI components
- Montserrat font for the beautiful typography