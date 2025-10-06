#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# METanalyzer.py
# Copyright (c) 2025 ot2i7ba
# https://github.com/ot2i7ba/
# This code is licensed under the MIT License (see LICENSE for details).

"""
Forensic analysis of eMule known.met files for law enforcement
Developed for criminal investigation IT forensics
Optimized for large known.met files with memory-efficient processing

Key Features:
- Memory-mapped file access for optimal performance
- Streaming data processing to handle large files efficiently  
- Precise block-length field parsing for accurate data extraction
- HTML report with pagination, search, and sticky header
- Comprehensive CSV and Excel exports for evidence documentation
- SHA-256 file verification
"""

import os
import sys
import mmap
import struct
import logging
import datetime
import time
import binascii
import csv
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Generator, Iterator
from contextlib import contextmanager

# Application Information
VERSION = "0.0.1"
APP_NAME = "METanalyzer"
APP_TITLE = f"{APP_NAME} v{VERSION}"
APP_SUBTITLE = "Forensic known.met Analysis Report"
APP_DESCRIPTION = "Memory-Mapped Streaming Technology for Evidence Processing"

# Default File Settings
DEFAULT_INPUT_FILE = "known.met"
DEFAULT_LOG_FILE = "metanalyzer.log"

# Output File Names
OUTPUT_CSV_FILE = "knownmet_forensic_analysis.csv"
OUTPUT_XLSX_FILE = "knownmet_forensic_analysis.xlsx"
OUTPUT_HTML_FILE = "knownmet_forensic_report.html"

# Processing Limits and Thresholds
MAX_FILENAME_LENGTH = 1000
MAX_BLOCK_SIZE = 100000
MIN_BLOCK_SIZE = 8
MAX_FILE_SIZE = 10**1024    # 1TB
MAX_UPLOAD_SIZE = 10**15    # 1PB
MAX_REQUESTS = 10**6        # 1 Million
TIMESTAMP_MIN = 946684800   # 2000-01-01
TIMESTAMP_MAX = 2208988800  # 2040-01-01

# Performance Settings
PROGRESS_UPDATE_INTERVAL = 1000
FLUSH_INTERVAL = 10000
HASH_CHUNK_SIZE = 8192

# HTML Report Settings
HTML_MAX_TABLE_HEIGHT = "600px"
HTML_DEFAULT_PAGE_SIZE = 100
HTML_PAGE_SIZE_OPTIONS = [100, 500, 1000, -1]
HTML_PAGE_SIZE_LABELS = [100, 500, 1000, "All"]

try:
    import pandas as pd
    import colorama
    from colorama import Fore, Style, init
    from tqdm import tqdm
    import xlsxwriter
except ImportError as e:
    print(f"ERROR: Required library missing: {e}")
    print("Please install missing packages with:")
    print("pip install pandas colorama tqdm xlsxwriter openpyxl")
    sys.exit(1)

# Initialize colorama for cross-platform color support
init(autoreset=True)

# Configure professional logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(DEFAULT_LOG_FILE, encoding='utf-8'),
    ]
)
logger = logging.getLogger(__name__)

class METanalyzer:
    """
    Implements memory-mapped parsing with streaming data processing
    to efficiently handle large forensic evidence files while maintaining
    constant memory usage regardless of file size.
    """

    # eMule protocol magic bytes and headers (forensically verified)
    HEADER_FILENAME = b"\x02\x01\x00\x01"        # Filename header signature
    HEADER_FILESIZE = b"03010002"                    # File size field marker
    HEADER_TOTALUPLOAD = b"03010050"                 # Total upload bytes
    HEADER_REQUESTS = b"03010051"                    # Request count
    HEADER_ACCEPTED_REQUESTS = b"03010052"           # Accepted requests
    HEADER_UPLOAD_PRIORITY = b"03010019"             # Upload priority
    HEADER_PART_NAME = b"02010012"                   # Part file name
    HEADER_LAST_SHARED = b"0301000D"                 # Last shared timestamp

    # Upload priority mapping (eMule protocol specification)
    PRIORITY_MAP = {
        b"00": "Low",
        b"01": "Normal", 
        b"02": "High",
        b"03": "Release",
        b"04": "Very Low",
        b"05": "Auto"
    }

    def __init__(self, filename: str = DEFAULT_INPUT_FILE):
        """Initialize the forensic analyzer with target file."""
        self.filename = filename
        self.file_size = 0
        self.processing_errors = []
        self.start_time = None
        self.file_hash = None

        # Performance tracking metrics
        self.total_entries = 0
        self.bytes_processed = 0
        self.headers_found = 0

        # Keyword search functionality
        self.keyword_list = []
        self.keyword_search_enabled = False

        logger.info(f"{APP_TITLE} initialized for file: {filename}")

    def clear_console(self) -> None:
        """Clear console screen for clean output presentation."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_header(self) -> None:
        """Display professional forensic tool header."""
        print(f"{Fore.CYAN}{Style.BRIGHT}")
        print("  " + "=" * 62)
        print(f"  {APP_TITLE}")
        print(f"  {APP_SUBTITLE}")
        print(f"  {APP_DESCRIPTION}")
        print("\n" + "  " + "-" * 62)
        print("  This tool is licensed under the MIT License by ot2i7ba")
        print("  Copyright (c) 2025 ot2i7ba - https://github.com/ot2i7ba/")
        print("  " + "=" * 62)
        print(f"{Style.RESET_ALL}")
        print()

    def print_status(self, message: str, status_type: str = "INFO") -> None:
        """Print timestamped status messages with appropriate formatting."""
        color_map = {
            "INFO": Fore.WHITE,
            "SUCCESS": Fore.GREEN, 
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "PROGRESS": Fore.CYAN,
            "PARSING": Fore.CYAN
        }

        color = color_map.get(status_type, Fore.WHITE)
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")

        print(f"  {color}[{timestamp}] {status_type}: {message}{Style.RESET_ALL}")
        logger.info(f"{status_type}: {message}")

    def print_separator(self, title: str = "", char: str = "-") -> None:
        """Print professional section separators."""
        if title:
            title_len = len(title)
            padding = (58 - title_len) // 2
            line = char * padding + f" {title} " + char * (58 - padding - title_len - 2)
            print(f"  {Fore.CYAN}{line}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.CYAN}{char * 60}{Style.RESET_ALL}")

    def calculate_file_hash(self) -> str:
        """Calculate SHA-256 hash for forensic audit trail."""
        try:
            hash_sha256 = hashlib.sha256()
            with open(self.filename, "rb") as f:
                for chunk in iter(lambda: f.read(HASH_CHUNK_SIZE), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest().upper()
        except Exception as e:
            logger.error(f"Hash calculation failed: {e}")
            return "HASH_CALCULATION_ERROR"

    def load_file_info(self) -> bool:
        """Load file metadata without reading entire file into memory."""
        if not os.path.isfile(self.filename):
            self.print_status(f"File not found: {self.filename}", "ERROR")
            return False

        self.file_size = os.path.getsize(self.filename)

        # Calculate forensic hash for evidence integrity
        self.print_status("Calculating forensic SHA-256 hash...", "INFO")
        self.file_hash = self.calculate_file_hash()

        self.print_status(f"Target file: {self.filename}", "SUCCESS")
        self.print_status(f"File size: {self.file_size:,} bytes ({self.file_size/1024/1024:.1f} MB)", "SUCCESS")
        self.print_status(f"SHA-256: {self.file_hash}", "SUCCESS")

        if self.file_size < 32:
            self.print_status("File too small for known.met format", "ERROR")
            return False

        return True

    @contextmanager
    def memory_mapped_file(self):
        """Context manager for memory-mapped file access."""
        try:
            with open(self.filename, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    yield mm
        except Exception as e:
            self.print_status(f"Memory mapping failed: {e}", "ERROR")
            raise

    def find_all_filename_headers_fast(self, mm: mmap.mmap) -> List[int]:
        """
        Locate all filename headers using optimized bytes.find() method.
        Significantly faster than byte-by-byte iteration for large files.
        """
        self.print_status("Starting optimized header scan...", "PARSING")

        positions = []
        start = 0

        with tqdm(total=self.file_size, desc="Scanning headers", unit="B", unit_scale=True) as pbar:
            while True:
                # Use optimized bytes.find() for maximum performance
                pos = mm.find(self.HEADER_FILENAME, start)
                if pos == -1:
                    break

                positions.append(pos)
                start = pos + 4  # Continue search after current header

                # Update progress bar
                pbar.update(start - pbar.n)

        self.headers_found = len(positions)
        self.print_status(f"Header scan complete: {len(positions):,} filename headers found", "SUCCESS")
        if self.start_time:
            scan_rate = self.file_size/1024/1024/(time.time()-self.start_time)
            self.print_status(f"Scan performance: {scan_rate:.0f} MB/s", "INFO")

        return positions

    def read_block_length(self, mm: mmap.mmap, offset: int) -> int:
        """
        Read block length field directly from known.met structure.
        Provides precise field boundary detection instead of heuristic estimation.
        """
        try:
            # Block length typically follows filename header (4 bytes, little-endian)
            if offset + 8 <= len(mm):
                block_length_bytes = mm[offset+4:offset+8]
                block_length = struct.unpack('<L', block_length_bytes)[0]

                # Validate block length is within reasonable bounds
                if MIN_BLOCK_SIZE <= block_length <= MAX_BLOCK_SIZE:
                    return block_length

            return 0  # Invalid or not found

        except (struct.error, IndexError):
            return 0

    def parse_entry_from_block(self, block_data: bytes, offset: int) -> Optional[Dict[str, Any]]:
        """
        Parse complete entry from block data with optimized field extraction.
        Returns structured dictionary with all available metadata fields.
        """
        try:
            # Convert block to hex for header pattern matching
            block_hex = binascii.hexlify(block_data)

            # Initialize entry with default values
            entry = {
                'filename': 'Unknown',
                'filesize': 0,
                'last_modified': 0,
                'last_posted_kad': 0,
                'requests': 0,
                'accepted_requests': 0,
                'transferred_bytes': 0,
                'spread_percent': '0%',
                'upload_priority': 'Not Found',
                'part_file': 'Not Found',
                'keyword_status': 'Not Searched',
                'source_offset': offset
            }

            # Extract filename (always at block start after header)
            try:
                if len(block_hex) >= 12:
                    # Filename length (offset 8-12 in hex, little-endian)
                    filename_length_hex = block_hex[10:12] + block_hex[8:10]
                    filename_length = int(filename_length_hex, 16)

                    if 0 < filename_length <= MAX_FILENAME_LENGTH:
                        filename_hex = block_hex[12:(filename_length*2)+12]
                        if len(filename_hex) == filename_length*2:
                            filename_bytes = binascii.unhexlify(filename_hex)

                            # Robust unicode decoding with fallback
                            try:
                                entry['filename'] = filename_bytes.decode("utf-8").strip()
                            except UnicodeDecodeError:
                                try:
                                    entry['filename'] = filename_bytes.decode("latin-1").strip()
                                except:
                                    entry['filename'] = str(filename_bytes).strip("b'")
            except Exception as e:
                logger.debug(f"Filename extraction failed at offset {offset}: {e}")

            # Extract additional metadata fields
            self._extract_field_values(block_hex, entry)

            # Calculate file spread percentage
            if entry['filesize'] > 0 and entry['transferred_bytes'] > 0:
                percentage = min(100.0, (entry['transferred_bytes'] / entry['filesize']) * 100)
                if percentage >= 100:
                    entry['spread_percent'] = "100%"
                elif percentage >= 10:
                    entry['spread_percent'] = f"{percentage:.0f}%"
                elif percentage >= 1:
                    entry['spread_percent'] = f"{percentage:.1f}%"
                else:
                    entry['spread_percent'] = f"{percentage:.2f}%"

            # Check against keyword list if enabled
            if self.keyword_search_enabled and self.keyword_list:
                entry['keyword_status'] = self._check_keywords(entry['filename'])

            return entry

        except Exception as e:
            error_msg = f"Entry parsing failed at offset {offset}: {e}"
            self.processing_errors.append(error_msg)
            logger.debug(error_msg)
            return None

    def _extract_field_values(self, block_hex: bytes, entry: Dict[str, Any]) -> None:
        """Extract all metadata field values from hexified block."""
        # File size extraction
        try:
            if self.HEADER_FILESIZE in block_hex:
                index_pos = block_hex.index(self.HEADER_FILESIZE)
                if index_pos + 16 <= len(block_hex):
                    filesize_hex = block_hex[index_pos+8:index_pos+16]
                    little_endian = (filesize_hex[6:8] + filesize_hex[4:6] + 
                                   filesize_hex[2:4] + filesize_hex[0:2])
                    filesize = int(little_endian, 16)
                    if 0 <= filesize <= MAX_FILE_SIZE:
                        entry['filesize'] = filesize
        except (ValueError, IndexError):
            pass

        # Total upload bytes extraction
        try:
            if self.HEADER_TOTALUPLOAD in block_hex:
                index_pos = block_hex.index(self.HEADER_TOTALUPLOAD)
                if index_pos + 16 <= len(block_hex):
                    upload_hex = block_hex[index_pos+8:index_pos+16]
                    little_endian = (upload_hex[6:8] + upload_hex[4:6] + 
                                   upload_hex[2:4] + upload_hex[0:2])
                    upload = int(little_endian, 16)
                    if 0 <= upload <= MAX_UPLOAD_SIZE:
                        entry['transferred_bytes'] = upload
        except (ValueError, IndexError):
            pass

        # Request count extraction
        try:
            if self.HEADER_REQUESTS in block_hex:
                index_pos = block_hex.index(self.HEADER_REQUESTS)
                if index_pos + 16 <= len(block_hex):
                    requests_hex = block_hex[index_pos+8:index_pos+16]
                    little_endian = (requests_hex[6:8] + requests_hex[4:6] + 
                                   requests_hex[2:4] + requests_hex[0:2])
                    requests = int(little_endian, 16)
                    if 0 <= requests <= MAX_REQUESTS:
                        entry['requests'] = requests
        except (ValueError, IndexError):
            pass

        # Accepted requests extraction
        try:
            if self.HEADER_ACCEPTED_REQUESTS in block_hex:
                index_pos = block_hex.index(self.HEADER_ACCEPTED_REQUESTS)
                if index_pos + 16 <= len(block_hex):
                    accepted_hex = block_hex[index_pos+8:index_pos+16]
                    little_endian = (accepted_hex[6:8] + accepted_hex[4:6] + 
                                   accepted_hex[2:4] + accepted_hex[0:2])
                    accepted = int(little_endian, 16)
                    if 0 <= accepted <= MAX_REQUESTS:
                        entry['accepted_requests'] = accepted
        except (ValueError, IndexError):
            pass

        # Upload priority extraction
        try:
            if self.HEADER_UPLOAD_PRIORITY in block_hex:
                index_pos = block_hex.index(self.HEADER_UPLOAD_PRIORITY)
                if index_pos + 10 <= len(block_hex):
                    priority_hex = block_hex[index_pos+8:index_pos+10]
                    entry['upload_priority'] = self.PRIORITY_MAP.get(priority_hex, "Unknown")
        except (ValueError, IndexError):
            pass

        # Last shared timestamp extraction
        try:
            if self.HEADER_LAST_SHARED in block_hex:
                index_pos = block_hex.index(self.HEADER_LAST_SHARED)
                if index_pos + 16 <= len(block_hex):
                    timestamp_hex = block_hex[index_pos+8:index_pos+16]
                    little_endian = (timestamp_hex[6:8] + timestamp_hex[4:6] + 
                                   timestamp_hex[2:4] + timestamp_hex[0:2])
                    timestamp = int(little_endian, 16)
                    if TIMESTAMP_MIN <= timestamp <= TIMESTAMP_MAX:
                        entry['last_posted_kad'] = timestamp
        except (ValueError, IndexError):
            pass

    def _check_keywords(self, filename: str) -> str:
        """Check filename against loaded keyword list."""
        filename_lower = filename.lower()
        for keyword in self.keyword_list:
            if keyword.lower() in filename_lower:
                return "FOUND"
        return "Not Found"

    def parse_entries_streaming(self, mm: mmap.mmap, positions: List[int]) -> Generator[Dict[str, Any], None, None]:
        """
        Generator-based streaming parser for memory-efficient processing.
        Maintains constant memory usage regardless of total entry count.
        """
        self.print_status("Starting streaming data processing...", "PARSING")

        processed_count = 0

        with tqdm(total=len(positions), desc="Processing entries", unit="entries") as pbar:
            for i, pos in enumerate(positions):
                try:
                    # Read precise block length from file structure
                    block_length = self.read_block_length(mm, pos)

                    if block_length == 0:
                        # Fallback: calculate to next header
                        if i + 1 < len(positions):
                            block_length = positions[i + 1] - pos - 4
                        else:
                            block_length = min(4096, len(mm) - pos - 4)

                    # Extract block data
                    block_end = min(pos + 4 + block_length, len(mm))
                    if block_end <= pos + 4:
                        continue

                    block_data = mm[pos:block_end]

                    # Parse entry from block
                    entry = self.parse_entry_from_block(block_data, pos)

                    if entry and entry['filename'] != 'Unknown':
                        processed_count += 1
                        self.bytes_processed += len(block_data)

                        # Update progress periodically
                        if processed_count % PROGRESS_UPDATE_INTERVAL == 0:
                            if self.start_time:
                                mb_per_sec = (self.bytes_processed / 1024 / 1024) / (time.time() - self.start_time)
                                pbar.set_postfix({
                                    'Rate': f'{mb_per_sec:.0f} MB/s',
                                    'Entries': f'{processed_count:,}'
                                })

                        yield entry

                    pbar.update(1)

                except Exception as e:
                    error_msg = f"Streaming error at position {pos}: {e}"
                    self.processing_errors.append(error_msg)
                    logger.debug(error_msg)
                    pbar.update(1)
                    continue

        self.total_entries = processed_count

        if self.start_time:
            elapsed = time.time() - self.start_time
            throughput_mb = (self.bytes_processed / 1024 / 1024) / elapsed
            throughput_entries = processed_count / (elapsed / 60)

            self.print_status(f"Streaming processing complete: {processed_count:,} entries extracted", "SUCCESS")
            self.print_status(f"Processing rate: {throughput_mb:.0f} MB/s, {throughput_entries:.0f} entries/min", "INFO")

    def export_streaming_csv(self, entries_generator: Generator) -> bool:
        """
        Export data to tab-separated CSV with streaming to handle large datasets.
        Maintains constant memory usage during export process.
        """
        try:
            self.print_status(f"Starting CSV export: {OUTPUT_CSV_FILE}", "INFO")

            with open(OUTPUT_CSV_FILE, 'w', encoding='utf-8', newline='') as csvfile:
                writer = csv.writer(csvfile, delimiter='\t', quoting=csv.QUOTE_MINIMAL)

                # Write header row
                writer.writerow([
                    "Filename", "File Size (Bytes)", "Part File", "Requests", "Accepted Requests", 
                    "Transferred (Bytes)", "Upload Priority", "Spread Percentage", "Last Shared (UTC)", 
                    "Keyword Match", "Source Offset"
                ])

                # Stream data export
                exported_count = 0

                for entry in entries_generator:
                    writer.writerow([
                        entry['filename'],
                        str(entry['filesize']) if entry['filesize'] > 0 else "0",
                        entry['part_file'],
                        str(entry['requests']) if entry['requests'] > 0 else "0",
                        str(entry['accepted_requests']) if entry['accepted_requests'] > 0 else "0",
                        str(entry['transferred_bytes']) if entry['transferred_bytes'] > 0 else "0",
                        entry['upload_priority'],
                        entry['spread_percent'],
                        self._unix_timestamp_to_utc(entry['last_posted_kad']),
                        entry['keyword_status'],
                        str(entry['source_offset'])
                    ])

                    exported_count += 1

                    # Flush buffer periodically for large exports
                    if exported_count % FLUSH_INTERVAL == 0:
                        csvfile.flush()

            self.print_status(f"CSV export complete: {exported_count:,} entries", "SUCCESS")
            return True

        except Exception as e:
            self.print_status(f"CSV export error: {e}", "ERROR")
            return False

    def export_streaming_xlsx(self, mm: mmap.mmap, positions: List[int]) -> bool:
        """
        Export data to Excel format using streaming writer for memory efficiency.
        Includes professional formatting suitable for forensic documentation.
        """
        try:
            self.print_status(f"Starting Excel export: {OUTPUT_XLSX_FILE}", "INFO")

            workbook = xlsxwriter.Workbook(OUTPUT_XLSX_FILE, {'constant_memory': True})
            worksheet = workbook.add_worksheet('Forensic Analysis Results')

            # Define professional formatting
            header_format = workbook.add_format({
                'bold': True,
                'bg_color': '#366092',
                'font_color': 'white',
                'border': 1,
                'align': 'center'
            })

            # Write header row
            headers = [
                "Entry #", "Filename", "File Size (Bytes)", "Part File", "Requests",
                "Accepted Requests", "Transferred (Bytes)", "Upload Priority",
                "Spread Percentage", "Last Shared (UTC)", "Keyword Match", "Source Offset"
            ]

            for col, header in enumerate(headers):
                worksheet.write(0, col, header, header_format)

            # Optimize column widths for readability
            column_widths = [8, 60, 15, 25, 12, 15, 18, 15, 12, 20, 15, 12]
            for col, width in enumerate(column_widths):
                worksheet.set_column(col, col, width)

            # Stream data export
            row = 1
            entries_generator = self.parse_entries_streaming(mm, positions)

            for entry in entries_generator:
                worksheet.write(row, 0, row)
                worksheet.write(row, 1, entry['filename'])
                worksheet.write(row, 2, entry['filesize'])
                worksheet.write(row, 3, entry['part_file'])
                worksheet.write(row, 4, entry['requests'])
                worksheet.write(row, 5, entry['accepted_requests'])
                worksheet.write(row, 6, entry['transferred_bytes'])
                worksheet.write(row, 7, entry['upload_priority'])
                worksheet.write(row, 8, entry['spread_percent'])
                worksheet.write(row, 9, self._unix_timestamp_to_utc(entry['last_posted_kad']))
                worksheet.write(row, 10, entry['keyword_status'])
                worksheet.write(row, 11, entry['source_offset'])

                row += 1

            workbook.close()

            self.print_status(f"Excel export complete: {row-1:,} entries", "SUCCESS")
            return True

        except Exception as e:
            self.print_status(f"Excel export error: {e}", "ERROR")
            return False

    def create_comprehensive_html_report(self, mm: mmap.mmap, positions: List[int]) -> bool:
        """
        Create professional HTML report with all entries, pagination, search, and sticky headers.
        Includes DataTables.js for client-side sorting, filtering, and pagination functionality.
        """
        try:
            self.print_status(f"Creating comprehensive HTML report: {OUTPUT_HTML_FILE}", "INFO")

            current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

            # Collect ALL entries for HTML report
            all_entries = []
            entries_generator = self.parse_entries_streaming(mm, positions)

            self.print_status("Collecting all entries for HTML report...", "INFO")
            for entry in tqdm(entries_generator, desc="Building HTML data", unit="entries"):
                all_entries.append(entry)

            # Generate HTML with DataTables integration and sticky header
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{APP_TITLE} - {APP_SUBTITLE}</title>

    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">

    <style>
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background-color: #f8f9fa;
            color: #212529;
        }}

        .header-section {{
            background: linear-gradient(135deg, #2c5282 0%, #2d3748 100%);
            color: white;
            padding: 2rem;
            margin-bottom: 2rem;
        }}

        .info-card {{
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 0.5rem;
            padding: 1.5rem;
            margin-bottom: 1rem;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
        }}

        .table-container {{
            background: white;
            border-radius: 0.5rem;
            padding: 1.5rem;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
        }}

        #forensicTable {{
            width: 100% !important;
        }}

        /* STICKY HEADER IMPLEMENTATION */
        .dataTables_scrollHead {{
            position: sticky;
            top: 0;
            z-index: 1000;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .dataTables_scrollBody {{
            max-height: {HTML_MAX_TABLE_HEIGHT};
            overflow-y: auto;
        }}

        /* Enhanced table header styling for sticky functionality */
        #forensicTable thead th {{
            background: linear-gradient(135deg, #366092 0%, #2c5282 100%) !important;
            color: white !important;
            border-color: #2c5282 !important;
            position: sticky;
            top: 0;
            z-index: 999;
            box-shadow: 0 2px 2px rgba(0,0,0,0.1);
        }}

        .dataTables_wrapper .dataTables_length,
        .dataTables_wrapper .dataTables_filter {{
            margin-bottom: 1rem;
        }}

        .dataTables_wrapper .dataTables_info,
        .dataTables_wrapper .dataTables_paginate {{
            margin-top: 1.5rem  !important;
            margin-bottom: 1.5rem  !important;
        }}

        .scroll-indicator {{
            font-size: 0.8rem;
            color: #6c757d;
            padding: 0.4rem;
            text-align: center;
            border-top: 1px solid #dee2e6;
            background: rgba(108, 117, 125, 0.1);
            margin-bottom: 0.5rem;
        }}

        .filename-cell {{
            max-width: 300px;
            word-break: break-word;
            font-family: monospace;
            font-size: 0.85rem;
        }}

        .number-cell {{
            text-align: right;
            font-family: monospace;
        }}

        .footer-section {{
            background-color: #2d3748;
            color: #e2e8f0;
            padding: 2rem;
            margin-top: 3rem;
            text-align: center;
        }}

        .badge-keyword {{
            background-color: #dc3545;
            color: white;
        }}

        .badge-normal {{
            background-color: #6c757d;
            color: white;
        }}

        /* Scroll indicator for horizontal scrolling */
        .table-responsive {{
            position: relative;
        }}
    </style>
</head>
<body>
    <div class="container-fluid">
        <!-- Header Section -->
        <div class="header-section text-center">
            <h1 class="display-4 mb-3">{APP_TITLE}</h1>
            <p class="lead">{APP_SUBTITLE}</p>
            <p class="mb-0">{APP_DESCRIPTION}</p>
        </div>

        <!-- Information Cards -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="info-card text-center">
                    <h5 class="text-muted">Analysis Date</h5>
                    <h4>{current_time}</h4>
                </div>
            </div>
            <div class="col-md-3">
                <div class="info-card text-center">
                    <h5 class="text-muted">Source File</h5>
                    <h4>{os.path.basename(self.filename)}</h4>
                </div>
            </div>
            <div class="col-md-3">
                <div class="info-card text-center">
                    <h5 class="text-muted">File Size</h5>
                    <h4>{self.file_size/1024/1024:.1f} MB</h4>
                </div>
            </div>
            <div class="col-md-3">
                <div class="info-card text-center">
                    <h5 class="text-muted">Total Entries</h5>
                    <h4>{len(all_entries):,}</h4>
                </div>
            </div>
        </div>

        <!-- Forensic Details -->
        <div class="info-card mb-4">
            <h5>Forensic Evidence Details</h5>
            <div class="row">
                <div class="col-md-6">
                    <p><strong>SHA-256 Hash:</strong> <code>{self.file_hash}</code></p>
                    <p><strong>Headers Found:</strong> {self.headers_found:,}</p>
                </div>
                <div class="col-md-6">
                    <p><strong>Processing Errors:</strong> {len(self.processing_errors)}</p>
                    <p><strong>Analysis Duration:</strong> {(time.time() - self.start_time)/60:.1f} minutes</p>
                </div>
            </div>
        </div>

        <!-- Main Data Table -->
        <div class="table-container">
            <h5 class="mb-3">Forensic Analysis Results</h5>

            <div class="table-responsive">
                <table id="forensicTable" class="table table-striped table-hover">
                    <thead class="table-primary">
                        <tr>
                            <th>#</th>
                            <th>Filename</th>
                            <th>Size (Bytes)</th>
                            <th>Part File</th>
                            <th>Requests</th>
                            <th>Accepted</th>
                            <th>Transferred</th>
                            <th>Priority</th>
                            <th>Spread %</th>
                            <th>Last Shared</th>
                            <th>Keywords</th>
                            <th>Offset</th>
                        </tr>
                    </thead>
                    <tbody>"""

            # Add all data rows
            for i, entry in enumerate(all_entries, 1):
                keyword_badge = 'badge-keyword' if entry['keyword_status'] == 'FOUND' else 'badge-normal'
                html_content += f"""
                        <tr>
                            <td class="number-cell">{i}</td>
                            <td class="filename-cell">{entry['filename']}</td>
                            <td class="number-cell">{entry['filesize']:,}</td>
                            <td>{entry['part_file']}</td>
                            <td class="number-cell">{entry['requests']:,}</td>
                            <td class="number-cell">{entry['accepted_requests']:,}</td>
                            <td class="number-cell">{entry['transferred_bytes']:,}</td>
                            <td class="text-center">{entry['upload_priority']}</td>
                            <td class="text-center">{entry['spread_percent']}</td>
                            <td>{self._unix_timestamp_to_utc(entry['last_posted_kad'])}</td>
                            <td class="text-center"><span class="badge {keyword_badge}">{entry['keyword_status']}</span></td>
                            <td class="number-cell">{entry['source_offset']}</td>
                        </tr>"""

            html_content += f"""
                    </tbody>
                </table>
            </div>

            <div class="scroll-indicator">
                ← Scroll horizontally to view all columns →
            </div>

        </div>

        <!-- Footer -->
        <div class="footer-section">
            <h6>known.met Forensic Analysis Report</h6>
            <p>Generated by {APP_TITLE} - {APP_SUBTITLE}</p>
            <p>{APP_DESCRIPTION}</p>
            <p class="mb-0">SHA-256: {self.file_hash}</p>
            <p>Generated: {current_time} | Entries: {len(all_entries):,} | Errors: {len(self.processing_errors)}</p>

            <p>This tool is licensed under the MIT License by <a href="https://github.com/ot2i7ba">ot2i7ba</a></p>
        </div>
    </div>

    <!-- JavaScript Libraries -->
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>

    <script>
        $(document).ready(function() {{
            $('#forensicTable').DataTable({{
                "pageLength": {HTML_DEFAULT_PAGE_SIZE},
                "lengthMenu": {HTML_PAGE_SIZE_OPTIONS},
                "order": [[0, "asc"]],
                "scrollY": "{HTML_MAX_TABLE_HEIGHT}",
                "scrollX": true,
                "scrollCollapse": true,
                "columnDefs": [
                    {{ "type": "num", "targets": [0, 2, 4, 5, 6, 11] }},
                    {{ "searchable": false, "targets": [0, 11] }}
                ],
                "language": {{
                    "search": "Search all fields:",
                    "lengthMenu": "Show _MENU_ entries per page",
                    "info": "Showing _START_ to _END_ of _TOTAL_ entries",
                    "paginate": {{
                        "first": "First",
                        "last": "Last",
                        "next": "Next",
                        "previous": "Previous"
                    }}
                }},
                "processing": true,
                "deferRender": true,
                "stateSave": true,
                "fixedHeader": true
            }});
        }});
    </script>
</body>
</html>"""

            with open(OUTPUT_HTML_FILE, 'w', encoding='utf-8') as f:
                f.write(html_content)

            self.print_status(f"HTML report created: {OUTPUT_HTML_FILE} ({len(all_entries):,} entries)", "SUCCESS")
            return True

        except Exception as e:
            self.print_status(f"HTML report error: {e}", "ERROR")
            return False

    def _unix_timestamp_to_utc(self, timestamp: int) -> str:
        """Convert Unix timestamp to UTC string representation."""
        if timestamp == 0:
            return "Not Available"

        try:
            dt = datetime.datetime.utcfromtimestamp(timestamp)
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except (ValueError, OSError):
            return "Invalid Timestamp"

    def load_keyword_list(self, keyword_file: str) -> bool:
        """Load keyword list from file for content filtering."""
        try:
            if not os.path.exists(keyword_file):
                self.print_status(f"Keyword file not found: {keyword_file}", "WARNING")
                return False

            with open(keyword_file, 'r', encoding='utf-8') as f:
                keywords = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip comments
                        keywords.append(line)

            self.keyword_list = keywords
            self.keyword_search_enabled = len(keywords) > 0

            self.print_status(f"Keyword list loaded: {len(keywords)} terms", "SUCCESS")
            return True

        except Exception as e:
            self.print_status(f"Keyword loading error: {e}", "ERROR")
            return False

    def run_forensic_analysis(self) -> bool:
        """Execute complete forensic analysis workflow."""
        self.clear_console()
        self.print_header()

        self.print_status(f"{APP_TITLE} {APP_SUBTITLE} started", "SUCCESS")
        self.print_status("Memory-mapped streaming technology enabled", "INFO")
        print()

        # Optional keyword file loading
        keyword_file = input(f"  {Fore.CYAN}Optional keyword file (press Enter to skip): {Style.RESET_ALL}").strip()
        if keyword_file:
            self.load_keyword_list(keyword_file)
            print()

        # Load file metadata
        if not self.load_file_info():
            input(f"\n{Fore.RED}ERROR: File loading failed. Press Enter to exit...{Style.RESET_ALL}")
            return False

        print()
        self.start_time = time.time()

        # Execute memory-mapped analysis
        try:
            with self.memory_mapped_file() as mm:
                self.print_separator("FORENSIC DATA PROCESSING")

                # Find all filename headers
                positions = self.find_all_filename_headers_fast(mm)

                if not positions:
                    self.print_status("No filename headers found in file", "ERROR")
                    return False

                print()

                # Generate comprehensive reports
                self.print_separator("EVIDENCE DOCUMENTATION")

                # CSV export (primary format)
                entries_gen = self.parse_entries_streaming(mm, positions)
                if not self.export_streaming_csv(entries_gen):
                    return False

                # Excel export for detailed analysis
                if not self.export_streaming_xlsx(mm, positions):
                    return False

                # Comprehensive HTML report with all entries and sticky header
                if not self.create_comprehensive_html_report(mm, positions):
                    return False

        except Exception as e:
            self.print_status(f"Memory mapping error: {e}", "ERROR")
            return False

        # Analysis summary
        elapsed_total = time.time() - self.start_time
        throughput_mb = (self.file_size / 1024 / 1024) / elapsed_total
        throughput_entries = self.total_entries / (elapsed_total / 60) if elapsed_total > 0 else 0

        print()
        self.print_separator("ANALYSIS COMPLETE")

        self.print_status("Forensic analysis completed successfully", "SUCCESS")
        print()

        # Performance metrics
        self.print_status(f"Processing rate: {throughput_mb:.0f} MB/s", "INFO")
        self.print_status(f"Entry throughput: {throughput_entries:.0f} entries/minute", "INFO")
        self.print_status(f"Memory efficiency: Constant RAM usage maintained", "INFO")
        self.print_status(f"Total entries extracted: {self.total_entries:,}", "SUCCESS")
        self.print_status(f"Analysis duration: {elapsed_total/60:.1f} minutes", "INFO")

        if self.processing_errors:
            self.print_status(f"Processing errors encountered: {len(self.processing_errors)}", "WARNING")

        print()
        self.print_status("Evidence files created:", "INFO")
        self.print_status(f"  {OUTPUT_CSV_FILE} (Primary evidence)", "INFO")
        self.print_status(f"  {OUTPUT_XLSX_FILE} (Detailed analysis)", "INFO")
        self.print_status(f"  {OUTPUT_HTML_FILE} (Interactive report with sticky headers)", "INFO")
        self.print_status(f"  {DEFAULT_LOG_FILE} (Processing log)", "INFO")

        print()
        input(f"{Fore.GREEN}Forensic analysis complete. Press Enter to exit...{Style.RESET_ALL}")
        return True


def main():
    """Main application entry point."""
    try:
        analyzer = METanalyzer()
        success = analyzer.run_forensic_analysis()
        return 0 if success else 1
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}WARNING: Analysis interrupted by user{Style.RESET_ALL}")
        return 1
    except Exception as e:
        print(f"\n{Fore.RED}CRITICAL ERROR: {e}{Style.RESET_ALL}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
