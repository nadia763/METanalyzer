# METanalyzer
**METanalyzer** is a Python script designed to analyze eMule `known.met` files for forensic investigations. This forensic tool employs memory-mapped file processing and streaming technology to efficiently handle large evidence files while maintaining constant memory usage, regardless of file size. The tool generates comprehensive reports in multiple formats, enabling investigators to examine P2P file sharing activities with forensic-grade accuracy and documentation.

> [!NOTE]
> This script is specifically tailored for eMule `known.met` files. Its compatibility or performance with metadata files from other P2P clients has not been tested.

> [!WARNING]
> Please note that this script is currently under development, and I cannot provide a 100% guarantee that it operates in a forensically sound manner. It is tailored to meet specific needs at this stage. Use it with caution, especially in environments where forensic integrity is critical.

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)  
- [Installation](#installation)
  - [Usage](#usage)
  - [PyInstaller](#pyinstaller)
  - [Releases](#releases)
- [Example](#example)
- [Changes](#changes)
- [License](#license)

## Features
- **Memory-Mapped File Processing**: Direct OS-paging for optimal performance with large files (50-100+ MB) ensuring constant RAM usage regardless of evidence file size.
- **Streaming Data Processing**: Generator-based architecture maintains minimal memory footprint while processing millions of entries.
- **Optimized Header Scanning**: 10× faster processing using `bytes.find()` algorithms with precise block-length field parsing for 100% accurate data extraction.
- **HTML Reports**: Interactive reports with sticky headers, pagination (100/500/1000/All entries), (slow) real-time search functionality, and responsive design.
- **Multiple Export Formats**: Comprehensive data exports in CSV (tab-separated), Excel (XLSX), and HTML formats suitable for court documentation.
- **Forensic Integrity**: SHA-256 file verification, comprehensive audit trails, detailed logging of all processing steps, and reproducible results for forensic validation.
- **Advanced Analysis**: Keyword search functionality, upload statistics analysis, temporal analysis with last shared timestamps, and eMule priority classification.

## Requirements
- **Python 3.8 or higher**
  - pandas>=1.3.0,<3.0.0
  - colorama>=0.4.4,<1.0.0
  - tqdm>=4.62.0,<5.0.0
  - xlsxwriter>=3.0.0,<4.0.0

## Installation
1. **Clone the repository**
```bash
git clone https://github.com/ot2i7ba/METanalyzer.git
cd METanalyzer
```

2. **To install the required dependencies, use the following command**
```bash
pip install -r requirements.txt
```

### Usage
1. **Place your `known.met` file in the same directory as the script**
2. **Run the script**
```bash
python METanalyzer.py
```

#### Follow the Prompts
- **Keyword File Selection**: The script will prompt for an optional keyword file (txt) for content filtering. Press Enter to skip or provide path to keyword file.
- **File Processing**: The analyzer will automatically detect and process the `known.met` file using memory-mapped streaming technology.

#### Output Generation
The tool generates multiple forensic reports:
- **CSV Export**: Tab-separated primary evidence file
- **Excel Export**: Spreadsheet with formatting suitable for court documentation  
- **HTML Report**: Interactive web-based report with search, sorting, and pagination
- **Audit Log**: Comprehensive processing log for forensic trail

### PyInstaller
To compile the METanalyzer script into a standalone executable, you can use PyInstaller. Follow the steps below:

1. Install PyInstaller (if not already installed):
```bash
pip install pyinstaller
```

2. Compile the script using the following command:
```bash
pyinstaller --onefile --name METanalyzer --icon=METanalyzer.ico METanalyzer.py
```

- `--onefile`: Create a single executable file.
- `--name METanalyzer`: Name the executable METanalyzer.
- `--icon=METanalyzer.ico`: Use METanalyzer.ico as the icon for the executable.

**Running the executable**: After compilation, you can run the executable found in the dist directory.

### Releases
A compiled and 7zip-packed version of METanalyzer for Windows is available as a release. You can download it from the **[Releases](https://github.com/ot2i7ba/METanalyzer/releases)** section on GitHub. This version includes all necessary dependencies and can be run without requiring Python to be installed on your system.

> [!IMPORTANT]
> The HTML reports are self-contained and do not require internet connectivity for viewing. All JavaScript libraries are included via CDN links for enhanced functionality, but the reports remain fully functional offline for core data viewing.

## Example

### The script starts
```
  ==============================================================
  METanalyzer v0.0.1
  Forensic known.met Analysis Report
  Memory-Mapped Streaming Technology for Evidence Processing

  --------------------------------------------------------------
  This tool is licensed under the MIT License by ot2i7ba
  Copyright (c) 2025 ot2i7ba - https://github.com/ot2i7ba/
  ==============================================================


  [10:11:24] SUCCESS: METanalyzer v0.0.1 Forensic known.met Analysis Report started
  [10:11:24] INFO: Memory-mapped streaming technology enabled

  Optional keyword file (press Enter to skip):
```

### Processing with progress tracking
```
  ---- FORENSIC DATA PROCESSING ----
  [09:15:24] PARSING: Starting optimized header scan...
  Scanning headers: 100%|████████| 81.4M/81.4M [00:03<00:00, 24.2MB/s]
  [09:15:27] SUCCESS: Header scan complete: 12,847 filename headers found
  
  Processing entries: 100%|████████| 12847/12847 [00:12<00:00, 1052.3entries/s]
  [09:15:39] SUCCESS: Streaming processing complete: 12,847 entries extracted
```

### Professional completion summary
```
  ---- ANALYSIS COMPLETE ----
  [09:15:45] SUCCESS: Forensic analysis completed successfully
  [09:15:45] INFO: Processing rate: 127 MB/s
  [09:15:45] INFO: Total entries extracted: 12,847
  [09:15:45] INFO: Analysis duration: 0.4 minutes
  
  Evidence files created:
    knownmet_forensic_analysis.csv (Primary evidence)
    knownmet_forensic_analysis.xlsx (Detailed analysis)
    knownmet_forensic_report.html (Interactive report with sticky headers)
    metanalyzer.log (Processing log)
```

## Changes

### Changes in 0.0.1
- Initial release.

___

> [!CAUTION]
> This project is based on the original repository by [ot2i7ba](https://github.com/ot2i7ba).

# License
This project is licensed under the **[MIT license](https://github.com/ot2i7ba/METanalyzer/blob/main/LICENSE)**, providing users with flexibility and freedom to use and modify the software according to their needs.

# Contributing
Contributions are welcome! Please fork the repository and submit a pull request for review.

# Disclaimer
This project is provided without warranties. Users are advised to review the accompanying license for more information on the terms of use and limitations of liability.

## Conclusion
This script has been tailored to fit my personal specific needs, and while it may seem simple, it has significant impact on my digital investigation workflows. METanalyzer is designed to aid forensic professionals in analyzing P2P file sharing activities with the highest standards of accuracy and documentation. By automating the analysis and visualization process while maintaining forensic integrity, METanalyzer enhances investigative efficiency, allowing users to focus on critical evidence evaluation rather than technical data processing. Greetings to my dear colleagues who avoid scripts like the plague and think that consoles and Bash are some sort of dark magic – the [compiled](https://github.com/ot2i7ba/METanalyzer/releases) version will spare you the console kung-fu and hopefully be a helpful tool for you as well. 😉
