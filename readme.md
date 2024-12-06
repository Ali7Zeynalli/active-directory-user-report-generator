This script was written by Ali Zeynalli and is used to retrieve and visualize detailed information about Active Directory users. 
Purpose and Overview
This PowerShell script creates a detailed, interactive HTML report of Active Directory users and their information. It's designed for system administrators to get a complete overview of their Active Directory environment.
Key Features:
Interactive HTML Dashboard
Shows total users, active users, deactivated accounts, and password statuses
Includes a search function to filter users
Interactive user rows that expand to show detailed information

User Information Collected
Basic user details (name, email, department)
Account status and security settings
Password information and expiration status
Login history and computer access
Network details and IP addresses
Group memberships
Organizational unit information

Performance Optimizations
Uses caching to reduce repeated AD queries
Implements parallel processing for faster execution
Processes users in batches
Includes progress tracking and recovery options

How to Use:
Prerequisites
Windows Server with Active Directory
PowerShell with Active Directory module
Administrative privileges

Running the Script
powershellCopy# Simply run the script in PowerShell:
.\AD_Report_Script.ps1

Output
Creates an HTML report in C:\Reports\AD\ directory
Automatically opens the report in default browser
File name includes date and time stamp

Benefits:
Comprehensive Overview: Get complete AD environment status
Easy to Use: Interactive web interface requires no technical knowledge
Visual Presentation: Color-coded statuses and organized information
Search Capability: Quickly find specific users
Performance: Optimized for large Active Directory environments
Recovery: Includes progress saving in case of interruption

Best Practices for Use:
Run during off-peak hours for large environments
Review the report periodically for security audits
Use for documentation and compliance purposes
Keep reports for historical tracking

This script is particularly useful for IT administrators who need to:
Audit Active Directory users
Track account statuses and security
Monitor password policies
Document AD environment
Investigate user access and permissions

The report provides both high-level statistics and detailed user information in an easy-to-navigate format, making it a valuable tool for Active Directory management and documentation.

![1e](https://github.com/user-attachments/assets/60a2d26b-aeb3-44c3-9222-b05b5b95cf56)
![2e](https://github.com/user-attachments/assets/6ff7aa79-3bb4-4187-8957-59654aa217f6)
![3e](https://github.com/user-attachments/assets/5e39eb54-7e14-4d32-a53f-7bd82635ffe2)
