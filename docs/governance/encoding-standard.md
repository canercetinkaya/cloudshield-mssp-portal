# CloudShield MSSP Platform - End-to-End UTF-8 Encoding Standard

## 1. Problem Statement
Windows console environments historically default to OEM/ANSI code pages, resulting in mojibake corruption of Turkish characters.

## 2. Architecture Boundary Corrections
1. PowerShell Engine: Enforce [Console]::OutputEncoding = UTF8 and UTF-8 file IO.
2. Python Server & Test Harness: Use encoding=utf-8, ensure_ascii=False, and configure console streams.
3. HTTP REST API: Content-Type headers explicitly declare charset=utf-8; Content-Disposition uses RFC 5987.
4. HTML & PDF: HTML meta charset=UTF-8; Chromium receives clean UTF-8 source.
