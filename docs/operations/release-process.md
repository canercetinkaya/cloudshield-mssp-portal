# CloudShield MSSP Platform - Release Automation Process

## 1. Overview
Releases are decoupled from continuous workspace synchronization and require execution through an explicit release gate command: New-CloudShieldRelease.ps1.

## 2. Release Prerequisites
1. Clean Working Tree: git status --porcelain must be clean.
2. Main Branch: Current branch must be main.
3. Full Quality Gate Pass: Python compilation, PowerShell test suite, comprehensive QA harness, version consistency, and UTF-8 encoding audit.
4. Immutable Tagging: Release tag (v2.5.11-PILOT) is created as an annotated tag without --force.
