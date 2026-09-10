# CloudShield MSSP Platform - Safe Git Synchronization Standard

## 1. Purpose
Automated workspace synchronization scripts must protect main branch stability and maintain developer confidentiality.

## 2. Synchronization Rules
1. No Direct Push to main: File watchers are forbidden from pushing directly to main.
2. Unique Branch Generation: Every synchronization event produces a dedicated tracking branch: sync/yyyyMMdd-HHmmss-shortsha.
3. Zero Automated Tagging: Git release tags cannot be created or overwritten by file watchers.
4. Strict Allow-List Staging: Only approved source files and documentation are staged. Unsafe paths (credentials, temporary files, caches) are rejected.
