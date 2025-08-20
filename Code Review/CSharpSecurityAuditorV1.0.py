#!/usr/bin/env python3
"""
Easy C# Security Auditor - Just point and scan!

Usage:
    python audit.py /path/to/your/csharp/project
    
Or make it executable:
    chmod +x audit.py
    ./audit.py /path/to/your/csharp/project
"""

import sys
import os
import argparse
from datetime import datetime
from pathlib import Path

# Import the main auditor (this should be in the same directory or in your Python path)
# If you saved the previous code as 'csharp_security_auditor.py', uncomment the next line:
# from csharp_security_auditor import CSharpSecurityAuditor

# For now, I'll include the auditor class here to make it a single file
import re
import json
from typing import List, Dict
from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

@dataclass
class SecurityIssue:
    file_path: str
    line_number: int
    issue_type: str
    severity: Severity
    description: str
    code_snippet: str
    recommendation: str

class CSharpSecurityAuditor:
    def __init__(self):
        self.issues: List[SecurityIssue] = []
        self.patterns = self._initialize_patterns()
        self.files_scanned = 0
        self.patterns_checked = {}
    
    def _initialize_patterns(self) -> Dict[str, Dict]:
        """Initialize security patterns based on OWASP guidelines"""
        return {
            # A01:2021 – Broken Access Control
            "missing_authorization": {
                "pattern": r"public\s+(?:async\s+)?(?:Task<)?(?:IActionResult|ActionResult|JsonResult|ViewResult)",
                "negative_pattern": r"\[Authorize",
                "severity": Severity.HIGH,
                "description": "Public action method without authorization attribute",
                "recommendation": "Add [Authorize] attribute to protect endpoints requiring authentication"
            },
            
            "allow_anonymous_sensitive": {
                "pattern": r"\[AllowAnonymous\][^}]*(?:Delete|Update|Create|Admin|Manage)",
                "severity": Severity.HIGH,
                "description": "Sensitive operation allows anonymous access",
                "recommendation": "Remove [AllowAnonymous] from sensitive operations"
            },
            
            # A02:2021 – Cryptographic Failures
            "weak_cryptography": {
                "pattern": r"\b(MD5|SHA1|DES|RC2|RC4)(?:CryptoServiceProvider|\.Create\(\)|\.ComputeHash)?\b",
                "severity": Severity.HIGH,
                "description": "Use of weak cryptographic algorithm",
                "recommendation": "Use strong algorithms like SHA256, SHA512, or AES"
            },
            
            "hardcoded_secrets": {
                "pattern": r'(?i)(?:password|pwd|passwd|secret|api[_-]?key|apikey|token|auth[_-]?token)\s*[:=]\s*["\'][^"\']{8,}["\']',
                "severity": Severity.CRITICAL,
                "description": "Hardcoded password or secret detected",
                "recommendation": "Store secrets in secure configuration or key vault"
            },
            
            "weak_key_size": {
                "pattern": r'(?:KeySize|keySize)\s*=\s*(?:512|768|1024)\b',
                "severity": Severity.MEDIUM,
                "description": "Weak cryptographic key size",
                "recommendation": "Use at least 2048 bits for RSA, 256 bits for AES"
            },
            
            "ecb_mode": {
                "pattern": r'CipherMode\.ECB',
                "severity": Severity.HIGH,
                "description": "ECB cipher mode is insecure",
                "recommendation": "Use CBC or GCM mode instead"
            },
            
            # A03:2021 – Injection
            "sql_injection": {
                "pattern": r'(?:ExecuteSqlCommand|ExecuteSqlRaw|FromSql|SqlQuery)\s*\([^)]*(?:\+|string\.Format|string\.Concat|\$")[^)]*\)',
                "severity": Severity.CRITICAL,
                "description": "Potential SQL injection vulnerability",
                "recommendation": "Use parameterized queries or stored procedures"
            },
            
            "command_injection": {
                "pattern": r'Process(?:\.Start|StartInfo)\s*\([^)]*(?:\+|string\.Format|string\.Concat|\$")[^)]*\)',
                "severity": Severity.CRITICAL,
                "description": "Potential command injection vulnerability",
                "recommendation": "Validate and sanitize all user input before using in system commands"
            },
            
            "ldap_injection": {
                "pattern": r'DirectorySearcher.*Filter\s*=.*\+',
                "severity": Severity.HIGH,
                "description": "Potential LDAP injection vulnerability",
                "recommendation": "Use parameterized LDAP queries"
            },
            
            "xpath_injection": {
                "pattern": r'SelectNodes\s*\([^)]*\+[^)]*\)|SelectSingleNode\s*\([^)]*\+[^)]*\)',
                "severity": Severity.HIGH,
                "description": "Potential XPath injection vulnerability",
                "recommendation": "Use parameterized XPath queries"
            },
            
            "script_injection": {
                "pattern": r'Response\.Write\s*\([^)]*(?:Request\.|ViewBag\.|TempData)',
                "severity": Severity.HIGH,
                "description": "Potential XSS vulnerability through Response.Write",
                "recommendation": "Use HTML encoding for user input"
            },
            
            # A04:2021 – Insecure Design
            "missing_input_validation": {
                "pattern": r'public\s+(?:async\s+)?(?:Task<)?(?:IActionResult|ActionResult).*\(([^)]+)\)',
                "negative_pattern": r'\[(?:Required|StringLength|Range|RegularExpression)',
                "severity": Severity.MEDIUM,
                "description": "Missing input validation attributes",
                "recommendation": "Add validation attributes to model properties"
            },
            
            "unsafe_type_conversion": {
                "pattern": r'Convert\.To(?:Int32|Int64|Double)\s*\([^)]*Request\.',
                "severity": Severity.MEDIUM,
                "description": "Unsafe type conversion from user input",
                "recommendation": "Use TryParse methods and validate input"
            },
            
            # A05:2021 – Security Misconfiguration
            "debug_enabled": {
                "pattern": r'<compilation\s+debug="true"',
                "severity": Severity.MEDIUM,
                "description": "Debug mode enabled in configuration",
                "recommendation": "Set debug='false' in production environments"
            },
            
            "custom_errors_off": {
                "pattern": r'<customErrors\s+mode="Off"',
                "severity": Severity.MEDIUM,
                "description": "Custom errors disabled",
                "recommendation": "Enable custom errors to prevent information disclosure"
            },
            
            "trace_enabled": {
                "pattern": r'<trace\s+enabled="true"',
                "severity": Severity.MEDIUM,
                "description": "Trace enabled in configuration",
                "recommendation": "Disable trace in production"
            },
            
            "request_validation_disabled": {
                "pattern": r'validateRequest="false"|ValidateRequest\s*=\s*false',
                "severity": Severity.HIGH,
                "description": "Request validation disabled",
                "recommendation": "Enable request validation to prevent XSS"
            },
            
            # A06:2021 – Vulnerable and Outdated Components
            "unsafe_deserialization": {
                "pattern": r'(?:BinaryFormatter|JavaScriptSerializer|XmlSerializer)\.Deserialize',
                "severity": Severity.HIGH,
                "description": "Use of unsafe deserialization",
                "recommendation": "Use safe serialization formats like JSON with proper type handling"
            },
            
            "obsolete_method": {
                "pattern": r'\[Obsolete\]|\[System\.Obsolete\]',
                "severity": Severity.LOW,
                "description": "Use of obsolete method or class",
                "recommendation": "Update to use current APIs"
            },
            
            # A07:2021 – Identification and Authentication Failures
            "weak_password_policy": {
                "pattern": r'PasswordValidator.*RequiredLength\s*=\s*(?:[1-7])\b',
                "severity": Severity.MEDIUM,
                "description": "Weak password length requirement",
                "recommendation": "Require passwords of at least 8 characters"
            },
            
            "missing_account_lockout": {
                "pattern": r'UserLockoutEnabledByDefault\s*=\s*false',
                "severity": Severity.MEDIUM,
                "description": "Account lockout disabled",
                "recommendation": "Enable account lockout to prevent brute force attacks"
            },
            
            "session_fixation": {
                "pattern": r'Session\[.*\]\s*=.*(?:Request\.|User\.Identity)',
                "severity": Severity.MEDIUM,
                "description": "Potential session fixation vulnerability",
                "recommendation": "Regenerate session ID after authentication"
            },
            
            # A08:2021 – Software and Data Integrity Failures
            "missing_antiforgery": {
                "pattern": r'<form.*method="post"',
                "negative_pattern": r'@Html\.AntiForgeryToken\(\)|asp-antiforgery="true"',
                "severity": Severity.HIGH,
                "description": "Missing anti-forgery token in form",
                "recommendation": "Add @Html.AntiForgeryToken() or asp-antiforgery='true'"
            },
            
            "missing_csrf_token": {
                "pattern": r'\[HttpPost\](?:(?!\[ValidateAntiForgeryToken\]).)*?public',
                "severity": Severity.HIGH,
                "description": "POST endpoint without anti-forgery token validation",
                "recommendation": "Add [ValidateAntiForgeryToken] attribute to POST actions"
            },
            
            # A09:2021 – Security Logging and Monitoring Failures
            "missing_logging": {
                "pattern": r'catch\s*\([^)]*\)\s*\{[^}]*\}',
                "negative_pattern": r'(?:Log|Logger|_logger)\.',
                "severity": Severity.LOW,
                "description": "Exception caught without logging",
                "recommendation": "Log security-relevant exceptions"
            },
            
            "sensitive_data_logging": {
                "pattern": r'(?:Log|Logger|_logger)\..*(?:password|pwd|ssn|creditcard|card)',
                "severity": Severity.HIGH,
                "description": "Potentially logging sensitive data",
                "recommendation": "Do not log sensitive information"
            },
            
            # A10:2021 – Server-Side Request Forgery (SSRF)
            "ssrf_vulnerability": {
                "pattern": r'(?:WebClient|HttpClient|WebRequest).*(?:DownloadString|GetAsync|Create)\s*\([^)]*\+[^)]*\)',
                "severity": Severity.HIGH,
                "description": "Potential SSRF vulnerability",
                "recommendation": "Validate and whitelist URLs before making requests"
            },
            
            # Additional patterns
            "path_traversal": {
                "pattern": r'(?:File|Directory)\.(?:ReadAllText|WriteAllText|Delete|Create|Exists)\s*\([^)]*\+[^)]*\)',
                "severity": Severity.HIGH,
                "description": "Potential path traversal vulnerability",
                "recommendation": "Validate and sanitize file paths"
            },
            
            "open_redirect": {
                "pattern": r'(?:Redirect|RedirectToAction)\s*\([^)]*(?:Request\.|ViewBag\.|TempData\[)',
                "severity": Severity.MEDIUM,
                "description": "Potential open redirect vulnerability",
                "recommendation": "Validate redirect URLs against a whitelist"
            },
            
            "insecure_random": {
                "pattern": r'new\s+Random\s*\(',
                "severity": Severity.MEDIUM,
                "description": "Use of insecure random number generator",
                "recommendation": "Use System.Security.Cryptography.RandomNumberGenerator for security-sensitive operations"
            },
            
            "random_usage": {
                "pattern": r'Random\s*\(\s*\)\s*\.\s*Next',
                "severity": Severity.MEDIUM,
                "description": "Insecure random number generation",
                "recommendation": "Use RandomNumberGenerator.GetInt32() for cryptographically secure random numbers"
            },
            
            "weak_random_seed": {
                "pattern": r'new\s+(?:System\.)?Random\s*\(\s*(?:DateTime\.Now\.(?:Ticks|Millisecond)|Environment\.TickCount)',
                "severity": Severity.MEDIUM,
                "description": "Predictable random seed",
                "recommendation": "Use cryptographically secure random number generator"
            },
            
            "xml_xxe": {
                "pattern": r'XmlReaderSettings.*DtdProcessing\s*=\s*DtdProcessing\.Parse',
                "severity": Severity.HIGH,
                "description": "XML External Entity (XXE) vulnerability",
                "recommendation": "Set DtdProcessing to Prohibit or Ignore"
            },
            
            # Additional Critical/High severity patterns
            "hardcoded_connectionstring": {
                "pattern": r'(?:ConnectionString|ConnString)\s*=\s*["\'][^"\']*(?:Password|Pwd|User ID|UID)=[^"\']+["\']',
                "severity": Severity.HIGH,
                "description": "Hardcoded connection string with credentials",
                "recommendation": "Use configuration files with encryption or Azure Key Vault"
            },
            
            "missing_https": {
                "pattern": r'["\']http://[^"\']+["\']',
                "severity": Severity.MEDIUM,
                "description": "Non-HTTPS URL detected",
                "recommendation": "Use HTTPS for all external communications"
            },
            
            "cookie_httponly": {
                "pattern": r'new\s+(?:Http)?Cookie\s*\([^)]*\)(?![^;{]*HttpOnly\s*=\s*true)',
                "severity": Severity.MEDIUM,
                "description": "Cookie without HttpOnly flag",
                "recommendation": "Set HttpOnly=true to prevent XSS attacks"
            },
            
            "cookie_secure": {
                "pattern": r'new\s+(?:Http)?Cookie\s*\([^)]*\)(?![^;{]*Secure\s*=\s*true)',
                "severity": Severity.MEDIUM,
                "description": "Cookie without Secure flag",
                "recommendation": "Set Secure=true for HTTPS-only cookies"
            },
            
            # Low severity patterns
            "empty_catch": {
                "pattern": r'catch\s*(?:\([^)]*\))?\s*\{\s*(?://[^\n]*)?\s*\}',
                "severity": Severity.LOW,
                "description": "Empty catch block",
                "recommendation": "Handle or log exceptions appropriately"
            },
            
            "todo_fixme": {
                "pattern": r'//\s*(?:TODO|FIXME|HACK|XXX)',
                "severity": Severity.LOW,
                "description": "TODO/FIXME comment found",
                "recommendation": "Address technical debt items"
            },
            
            "console_writeline": {
                "pattern": r'Console\.Write(?:Line)?\s*\(',
                "severity": Severity.LOW,
                "description": "Console output in production code",
                "recommendation": "Use proper logging framework"
            },
            
            "unsafe_string_comparison": {
                "pattern": r'\.Equals\s*\([^)]*StringComparison\.(?:CurrentCulture|InvariantCulture)\)',
                "severity": Severity.LOW,
                "description": "Culture-dependent string comparison in security context",
                "recommendation": "Use StringComparison.Ordinal for security-sensitive comparisons"
            },
            
            "missing_disposed_pattern": {
                "pattern": r'class\s+\w+\s*:\s*IDisposable\s*\{(?:(?!Dispose\s*\().)*\}',
                "severity": Severity.LOW,
                "description": "IDisposable implementation without Dispose method",
                "recommendation": "Implement proper Dispose pattern to prevent resource leaks"
            },
            
            "unsafe_file_upload": {
                "pattern": r'\.(?:SaveAs|WriteAllBytes)\s*\([^)]*Request\.Files',
                "severity": Severity.HIGH,
                "description": "File upload without validation",
                "recommendation": "Validate file type, size, and content before saving"
            },
            
            "exposed_stack_trace": {
                "pattern": r'catch\s*\([^)]*\)\s*\{[^}]*Response\.Write\s*\(\s*(?:ex|exception)\.StackTrace',
                "severity": Severity.MEDIUM,
                "description": "Stack trace exposed to user",
                "recommendation": "Log stack traces server-side, show generic error messages to users"
            },
            
            "unsafe_regex": {
                "pattern": r'new\s+Regex\s*\([^,)]*(?:Request\.|ViewBag\.|TempData)',
                "severity": Severity.HIGH,
                "description": "User input in regex pattern (ReDoS vulnerability)",
                "recommendation": "Validate and sanitize user input before using in regex patterns"
            },
            
            "missing_timeout": {
                "pattern": r'new\s+(?:HttpClient|WebClient|SqlCommand)\s*\([^)]*\)(?![^;{]*(?:Timeout|CommandTimeout)\s*=)',
                "severity": Severity.LOW,
                "description": "Network operation without timeout",
                "recommendation": "Set appropriate timeouts to prevent resource exhaustion"
            },
            
            "unsafe_temp_file": {
                "pattern": r'Path\.GetTempFileName\s*\(\s*\)',
                "severity": Severity.MEDIUM,
                "description": "Predictable temporary file name",
                "recommendation": "Use Path.GetRandomFileName() or GUID for temporary files"
            },
            
            # Thread safety
            "static_mutable": {
                "pattern": r'static\s+(?!readonly|const)[^;]*(?:List|Dictionary|HashSet|Collection)',
                "severity": Severity.MEDIUM,
                "description": "Static mutable collection - potential thread safety issue",
                "recommendation": "Use thread-safe collections or proper synchronization"
            },
            
            "double_checked_locking": {
                "pattern": r'if\s*\([^)]*==\s*null\s*\)[^{]*lock[^{]*if\s*\([^)]*==\s*null\s*\)',
                "severity": Severity.LOW,
                "description": "Double-checked locking pattern detected",
                "recommendation": "Use Lazy<T> or proper synchronization"
            },
            
            # Test patterns for common scenarios
            "test_http_url": {
                "pattern": r'(?i)(?:url|endpoint|baseurl|uri)\s*[:=]\s*["\']http://[^"\']+["\']',
                "severity": Severity.MEDIUM,
                "description": "HTTP URL in configuration or code",
                "recommendation": "Use HTTPS for secure communications"
            },
            
            "random_for_security": {
                "pattern": r'(?i)(?:token|salt|nonce|key|password).*=.*new\s+Random\(',
                "severity": Severity.HIGH,
                "description": "Using Random() for security-sensitive values",
                "recommendation": "Use RandomNumberGenerator.GetBytes() for cryptographic purposes"
            },
            
            "guid_for_security": {
                "pattern": r'(?i)(?:token|session|auth).*=.*Guid\.NewGuid\(',
                "severity": Severity.MEDIUM,
                "description": "Using GUID for security tokens",
                "recommendation": "Use RandomNumberGenerator for cryptographically secure tokens"
            }
        }
    
    def audit_file(self, file_path: str) -> List[SecurityIssue]:
        """Audit a single C# file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            file_issues = []
            found_issues = set()  # Track unique issues to avoid duplicates
            
            for pattern_name, pattern_info in self.patterns.items():
                # Skip patterns without a regex pattern
                if "pattern" not in pattern_info:
                    continue
                    
                # Track that we checked this pattern
                self.patterns_checked[pattern_name] = self.patterns_checked.get(pattern_name, 0) + 1
                
                # Check for positive patterns
                try:
                    pattern = pattern_info["pattern"]
                    # Use both MULTILINE and IGNORECASE flags
                    matches = list(re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE))
                    
                    # Debug output for Random detection
                    if pattern_name == "insecure_random":
                        if "new Random" in content:
                            print(f"DEBUG: File {os.path.basename(file_path)} contains 'new Random'")
                        if matches:
                            print(f"DEBUG: Found {len(matches)} matches for insecure_random")
                    
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        # Create unique key for this issue
                        issue_key = (file_path, line_num, pattern_name)
                        if issue_key in found_issues:
                            continue
                        found_issues.add(issue_key)
                        
                        # Check for negative patterns (things that should be present)
                        if "negative_pattern" in pattern_info:
                            # Look for negative pattern in surrounding context
                            start_line = max(0, line_num - 10)
                            end_line = min(len(lines), line_num + 10)
                            context = '\n'.join(lines[start_line:end_line])
                            
                            if re.search(pattern_info["negative_pattern"], context, re.IGNORECASE):
                                continue
                        
                        # Extract code snippet
                        snippet_start = max(0, line_num - 2)
                        snippet_end = min(len(lines), line_num + 2)
                        code_snippet = '\n'.join(lines[snippet_start:snippet_end])
                        
                        issue = SecurityIssue(
                            file_path=file_path,
                            line_number=line_num,
                            issue_type=pattern_name,
                            severity=pattern_info["severity"],
                            description=pattern_info["description"],
                            code_snippet=code_snippet,
                            recommendation=pattern_info["recommendation"]
                        )
                        
                        file_issues.append(issue)
                except re.error as e:
                    print(f"Regex error in pattern '{pattern_name}': {str(e)}")
                    continue
            
            return file_issues
            
        except Exception as e:
            print(f"Error auditing file {file_path}: {str(e)}")
            import traceback
            traceback.print_exc()
            return []
    
    def audit_directory(self, directory_path: str, extensions: List[str] = None) -> List[SecurityIssue]:
        """Audit all C# files in a directory"""
        if extensions is None:
            extensions = ['.cs', '.cshtml', '.aspx', '.config', '.json']
        
        all_issues = []
        self.files_scanned = 0
        # Initialize patterns_checked with ALL pattern names including JSON
        self.patterns_checked = {}
        for pattern_name in self.patterns.keys():
            self.patterns_checked[pattern_name] = 0
        self.patterns_checked["hardcoded_secrets_json"] = 0
        
        for root, dirs, files in os.walk(directory_path):
            # Skip common directories to ignore
            dirs[:] = [d for d in dirs if d not in ['bin', 'obj', '.git', 'packages', 'node_modules']]
            
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    # Special handling for JSON files
                    if file.endswith('.json'):
                        issues = self.audit_json_file(file_path)
                    else:
                        issues = self.audit_file(file_path)
                    all_issues.extend(issues)
                    self.files_scanned += 1
        
        self.issues = all_issues
        return all_issues
    
    def audit_json_file(self, file_path: str) -> List[SecurityIssue]:
        """Audit JSON configuration files for security issues"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            issues = []
            found_issues = set()  # Track unique issues to avoid duplicates
            
            # Pattern for passwords and secrets in JSON
            json_patterns = [
                (r'"(?:password|pwd|secret|api[_-]?key|token|connectionstring)"\s*:\s*"[^"]{3,}"', "hardcoded_secrets_json"),
                (r'"(?:Password|Pwd|Secret|Api[_-]?Key|Token|ConnectionString)"\s*:\s*"[^"]{3,}"', "hardcoded_secrets_json")
            ]
            
            # Track that we checked this pattern
            self.patterns_checked["hardcoded_secrets_json"] = self.patterns_checked.get("hardcoded_secrets_json", 0) + 1
            
            for pattern, issue_type in json_patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    
                    # Create unique key for this issue
                    issue_key = (file_path, line_num, issue_type)
                    if issue_key in found_issues:
                        continue
                    found_issues.add(issue_key)
                    
                    # Extract the matched text
                    matched_text = match.group(0)
                    
                    # Skip if it's a placeholder or example
                    if any(placeholder in matched_text.lower() for placeholder in ['example', 'placeholder', 'your-', 'xxx', '***', '...', 'todo', 'changeme', '<']):
                        continue
                    
                    # Extract code snippet
                    snippet_start = max(0, line_num - 2)
                    snippet_end = min(len(lines), line_num + 2)
                    code_snippet = '\n'.join(lines[snippet_start:snippet_end])
                    
                    issue = SecurityIssue(
                        file_path=file_path,
                        line_number=line_num,
                        issue_type=issue_type,
                        severity=Severity.CRITICAL,
                        description="Hardcoded password or secret detected in configuration file",
                        code_snippet=code_snippet,
                        recommendation="Move secrets to environment variables, Azure Key Vault, or use Secret Manager"
                    )
                    
                    issues.append(issue)
            
            return issues
            
        except Exception as e:
            print(f"Error auditing JSON file {file_path}: {str(e)}")
            return []
    
    def generate_report(self, output_format: str = "console") -> str:
        """Generate audit report"""
        if output_format == "console":
            return self._generate_console_report()
        elif output_format == "json":
            return self._generate_json_report()
        elif output_format == "html":
            return self._generate_html_report()
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def _generate_console_report(self) -> str:
        """Generate console-friendly report"""
        report = ["=" * 80]
        report.append("OWASP C# Security Audit Report")
        report.append("=" * 80)
        report.append(f"\nTotal Issues Found: {len(self.issues)}\n")
        
        # Group by severity
        by_severity = {}
        for issue in self.issues:
            if issue.severity not in by_severity:
                by_severity[issue.severity] = []
            by_severity[issue.severity].append(issue)
        
        # Summary
        report.append("Summary by Severity:")
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = len(by_severity.get(severity, []))
            if count > 0:
                report.append(f"  {severity.value}: {count} issues")
        
        # Report by severity
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if severity in by_severity:
                report.append(f"\n\n{severity.value} Severity Issues ({len(by_severity[severity])})")
                report.append("-" * 40)
                
                for issue in by_severity[severity]:
                    report.append(f"\nFile: {issue.file_path}")
                    report.append(f"Line: {issue.line_number}")
                    report.append(f"Type: {issue.issue_type}")
                    report.append(f"Description: {issue.description}")
                    report.append(f"Recommendation: {issue.recommendation}")
                    report.append(f"Code:\n{issue.code_snippet}")
                    report.append("-" * 40)
        
        return '\n'.join(report)
    
    def _generate_json_report(self) -> str:
        """Generate JSON report"""
        report_data = {
            "scan_date": datetime.now().isoformat(),
            "total_issues": len(self.issues),
            "summary": {},
            "issues": []
        }
        
        # Add summary
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = len([i for i in self.issues if i.severity == severity])
            if count > 0:
                report_data["summary"][severity.value] = count
        
        # Add issues
        report_data["issues"] = [
            {
                "file_path": issue.file_path,
                "line_number": issue.line_number,
                "issue_type": issue.issue_type,
                "severity": issue.severity.value,
                "description": issue.description,
                "recommendation": issue.recommendation,
                "code_snippet": issue.code_snippet
            }
            for issue in self.issues
        ]
        
        return json.dumps(report_data, indent=2)
    
    def _generate_html_report(self) -> str:
        """Generate HTML report with navigation and comprehensive coverage"""
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>OWASP C# Security Audit Report</title>
    <style>
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; 
            margin: 0; 
            padding: 0;
            background-color: #f8f9fa; 
        }}
        .container {{ 
            max-width: 1400px; 
            margin: 0 auto; 
            background-color: white; 
            box-shadow: 0 0 20px rgba(0,0,0,0.05); 
            display: flex;
            min-height: 100vh;
        }}
        
        /* Navigation Sidebar */
        .sidebar {{
            width: 300px;
            background: linear-gradient(180deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 20px;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
            box-shadow: 2px 0 10px rgba(0,0,0,0.1);
        }}
        .sidebar h1 {{
            font-size: 1.5em;
            margin: 0 0 20px 0;
            padding-bottom: 20px;
            border-bottom: 2px solid rgba(255,255,255,0.1);
        }}
        .sidebar h2 {{
            color: white;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 25px;
            margin-bottom: 10px;
            opacity: 0.7;
        }}
        .nav-link {{
            display: block;
            color: rgba(255,255,255,0.9);
            text-decoration: none;
            padding: 10px 15px;
            margin: 2px 0;
            border-radius: 6px;
            transition: all 0.3s ease;
            font-size: 0.95em;
            cursor: pointer;
        }}
        .nav-link:hover {{
            background-color: rgba(255,255,255,0.1);
            transform: translateX(5px);
        }}
        .nav-link.active {{
            background-color: #3498db;
            box-shadow: 0 2px 8px rgba(52,152,219,0.3);
        }}
        
        /* Main Content */
        .main-content {{
            margin-left: 300px;
            padding: 40px;
            width: calc(100% - 300px);
        }}
        
        /* Status Colors */
        .critical {{ color: #e74c3c; font-weight: 600; }}
        .high {{ color: #e67e22; font-weight: 600; }}
        .medium {{ color: #f39c12; font-weight: 600; }}
        .low {{ color: #27ae60; }}
        .info {{ color: #3498db; }}
        .success {{ color: #27ae60; font-weight: 500; }}
        
        /* Header */
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 2.5em;
        }}
        .header .timestamp {{
            opacity: 0.9;
            font-size: 1em;
        }}
        
        /* Summary Cards */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .summary-card {{
            background: white;
            border: 1px solid #e9ecef;
            border-radius: 12px;
            padding: 25px;
            text-align: center;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}
        .summary-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        }}
        .summary-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.08);
        }}
        .summary-card.critical::before {{ background: #e74c3c; }}
        .summary-card.high::before {{ background: #e67e22; }}
        .summary-card.medium::before {{ background: #f39c12; }}
        .summary-card.low::before {{ background: #27ae60; }}
        
        .summary-card h3 {{
            margin: 0 0 5px 0;
            font-size: 3em;
            font-weight: 300;
        }}
        .summary-card p {{
            margin: 0;
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        /* Coverage Report */
        .coverage-section {{
            background: white;
            border-radius: 12px;
            padding: 0;
            margin: 30px 0;
            border: 1px solid #e9ecef;
            overflow: hidden;
        }}
        .coverage-header {{
            background: #f8f9fa;
            padding: 20px 30px;
            border-bottom: 1px solid #e9ecef;
        }}
        .coverage-header h3 {{
            margin: 0;
            color: #2c3e50;
        }}
        .coverage-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(450px, 1fr));
            gap: 0;
        }}
        .coverage-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 30px;
            border-bottom: 1px solid #f0f0f0;
            border-right: 1px solid #f0f0f0;
            transition: background-color 0.2s ease;
        }}
        .coverage-item:hover {{
            background-color: #f8f9fa;
        }}
        .coverage-item-info {{
            flex: 1;
        }}
        .coverage-item-status {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .status-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 500;
        }}
        .status-badge.found {{
            background-color: #fee4e2;
            color: #e74c3c;
        }}
        .status-badge.clear {{
            background-color: #d1fae5;
            color: #065f46;
        }}
        .severity-badge {{
            font-size: 0.8em;
            padding: 2px 8px;
            border-radius: 4px;
            background-color: #f0f0f0;
            color: #6c757d;
        }}
        
        /* Issues */
        .issue {{ 
            background: white;
            border: 1px solid #e9ecef; 
            margin: 20px 0; 
            padding: 0; 
            border-radius: 12px;
            overflow: hidden;
            transition: all 0.3s ease;
        }}
        .issue:hover {{ 
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            transform: translateY(-2px);
        }}
        .issue-header {{
            background: #f8f9fa;
            padding: 20px 25px;
            border-bottom: 1px solid #e9ecef;
        }}
        .issue-content {{
            padding: 20px 25px;
        }}
        .issue-meta {{
            display: flex;
            gap: 20px;
            color: #6c757d;
            font-size: 0.9em;
            margin-top: 10px;
        }}
        .code {{ 
            background: #2d3748; 
            color: #e2e8f0;
            padding: 20px; 
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace; 
            border-radius: 8px; 
            overflow-x: auto;
            margin: 15px 0;
            font-size: 0.9em;
            line-height: 1.5;
        }}
        
        /* Utility Classes */
        .section {{ 
            margin: 40px 0;
            scroll-margin-top: 20px;
        }}
        h2 {{ 
            color: #2c3e50; 
            font-size: 1.8em;
            margin-bottom: 20px;
        }}
        h3 {{
            color: #34495e;
            margin-top: 0;
        }}
        h4 {{
            margin: 0;
            font-size: 1.2em;
        }}
        
        /* Back to top button */
        .back-to-top {{
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: #3498db;
            color: white;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            text-decoration: none;
            box-shadow: 0 4px 12px rgba(52,152,219,0.3);
            transition: all 0.3s ease;
            font-size: 1.2em;
        }}
        .back-to-top:hover {{
            transform: translateY(-3px);
            box-shadow: 0 6px 20px rgba(52,152,219,0.4);
        }}
        
        /* Print styles */
        @media print {{
            .sidebar, .back-to-top {{ display: none; }}
            .main-content {{ margin-left: 0; width: 100%; padding: 20px; }}
            .issue {{ break-inside: avoid; }}
            .header {{ background: #667eea; print-color-adjust: exact; }}
        }}
        
        /* Responsive */
        @media (max-width: 768px) {{
            .sidebar {{ display: none; }}
            .main-content {{ margin-left: 0; width: 100%; padding: 20px; }}
            .coverage-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
    <script>
        function scrollToSection(id) {{
            const element = document.getElementById(id);
            if (element) {{
                element.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
                
                // Update active nav
                document.querySelectorAll('.nav-link').forEach(link => {{
                    link.classList.remove('active');
                }});
                const activeLink = document.querySelector(`[onclick="scrollToSection('${{id}}')"]`);
                if (activeLink) {{
                    activeLink.classList.add('active');
                }}
            }}
            return false;
        }}
        
        // Show/hide back to top button
        window.addEventListener('scroll', function() {{
            const backToTop = document.querySelector('.back-to-top');
            if (window.pageYOffset > 300) {{
                backToTop.style.display = 'flex';
            }} else {{
                backToTop.style.display = 'none';
            }}
        }});
    </script>
</head>
<body>
    <!-- Navigation Sidebar -->
    <div class="sidebar">
        <h1>🛡️ Security Audit</h1>
        <h2>Quick Navigation</h2>
        <a class="nav-link active" onclick="return scrollToSection('summary')">📊 Summary</a>
        <a class="nav-link" onclick="return scrollToSection('coverage')">📈 Coverage Report</a>
        <a class="nav-link" onclick="return scrollToSection('findings')">🔍 All Findings</a>
        
        <h2>By Severity</h2>
        {severity_nav}
        
        <h2>By Type</h2>
        {type_nav}
    </div>
    
    <!-- Main Content -->
    <div class="main-content">
        <div class="header">
            <h1>OWASP C# Security Audit Report</h1>
            <p class="timestamp">Generated: {timestamp}</p>
            <p class="timestamp">Files Scanned: {files_scanned} | Patterns Checked: {patterns_count}</p>
        </div>
        
        <div id="summary" class="section">
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                {summary_cards}
            </div>
        </div>
        
        <div id="coverage" class="section">
            <h2>📈 Security Coverage Report</h2>
            <div class="coverage-section">
                <div class="coverage-header">
                    <h3>Security Patterns Checked</h3>
                </div>
                <div class="coverage-grid">
                    {coverage_report}
                </div>
            </div>
        </div>
        
        <div id="findings" class="section">
            <h2>🔍 Detailed Findings</h2>
            {issues}
        </div>
        
        <div class="section">
            <h2>📋 Recommendations</h2>
            <ol style="line-height: 1.8;">
                <li><strong>Address Critical Issues First:</strong> Focus on SQL injection, command injection, and hardcoded secrets</li>
                <li><strong>Implement Security Controls:</strong> Add authorization attributes, input validation, and proper error handling</li>
                <li><strong>Update Dependencies:</strong> Replace weak cryptographic algorithms with modern alternatives</li>
                <li><strong>Regular Audits:</strong> Run this tool as part of your CI/CD pipeline</li>
                <li><strong>Security Training:</strong> Ensure developers understand OWASP Top 10 vulnerabilities</li>
            </ol>
        </div>
    </div>
    
    <a href="#" class="back-to-top" onclick="window.scrollTo({{top: 0, behavior: 'smooth'}}); return false;">↑</a>
</body>
</html>
"""
        
        # Generate navigation items
        by_severity = {}
        by_type = {}
        for issue in self.issues:
            if issue.severity not in by_severity:
                by_severity[issue.severity] = []
            by_severity[issue.severity].append(issue)
            
            if issue.issue_type not in by_type:
                by_type[issue.issue_type] = []
            by_type[issue.issue_type].append(issue)
        
        # Severity navigation
        severity_nav = []
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if severity in by_severity:
                count = len(by_severity[severity])
                severity_nav.append(f'<a class="nav-link" onclick="return scrollToSection(\'severity-{severity.value.lower()}\')">{severity.value} ({count})</a>')
        
        # Type navigation - fix the IDs to be valid HTML IDs
        type_nav = []
        for issue_type, issues in sorted(by_type.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
            readable_type = issue_type.replace('_', ' ').title()
            # Create valid HTML ID by replacing underscores with hyphens
            type_id = issue_type.replace('_', '-')
            type_nav.append(f'<a class="nav-link" onclick="return scrollToSection(\'type-{type_id}\')">{readable_type} ({len(issues)})</a>')
        
        # Generate summary cards
        summary_cards = []
        total_issues = len(self.issues)
        
        # Total issues card
        summary_cards.append(f'''
            <div class="summary-card">
                <h3>{total_issues}</h3>
                <p>Total Issues</p>
            </div>
        ''')
        
        # Severity cards
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            if severity in by_severity:
                count = len(by_severity[severity])
                summary_cards.append(f'''
                    <div class="summary-card {severity.value.lower()}">
                        <h3 class="{severity.value.lower()}">{count}</h3>
                        <p>{severity.value} Severity</p>
                    </div>
                ''')
        
        # Coverage report
        coverage_items = []
        patterns_found = {issue.issue_type for issue in self.issues}
        
        # Create a combined patterns dict including ALL patterns
        all_patterns = dict(self.patterns)
        all_patterns["hardcoded_secrets_json"] = {
            "severity": Severity.CRITICAL,
            "description": "Hardcoded password or secret detected in configuration file",
            "recommendation": "Move secrets to environment variables, Azure Key Vault, or use Secret Manager"
        }
        
        # Sort patterns by severity for better organization
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        sorted_patterns = sorted(all_patterns.items(), 
                               key=lambda x: (severity_order.get(x[1].get("severity", Severity.MEDIUM), 5), x[0]))
        
        # Ensure all patterns are tracked
        for pattern_name in all_patterns.keys():
            if pattern_name not in self.patterns_checked:
                self.patterns_checked[pattern_name] = 0
        
        for pattern_name, pattern_info in sorted_patterns:
            checked_count = self.patterns_checked.get(pattern_name, 0)
            found_count = len([i for i in self.issues if i.issue_type == pattern_name])
            
            # Special handling for different pattern names
            readable_name = pattern_name.replace('_', ' ').title()
            if pattern_name == "hardcoded_secrets_json":
                readable_name = "Hardcoded Secrets in JSON"
            elif pattern_name == "random_usage":
                readable_name = "Random().Next() Usage"
            elif pattern_name == "insecure_random":
                readable_name = "new Random() Usage"
            elif pattern_name == "missing_https":
                readable_name = "HTTP URLs (Missing HTTPS)"
            elif pattern_name == "test_http_url":
                readable_name = "HTTP URL in Config/Code"
            
            status_icon = "✅" if found_count == 0 else "⚠️"
            status_text = "Clear" if found_count == 0 else f"{found_count} found"
            badge_class = "clear" if found_count == 0 else "found"
            severity = pattern_info.get("severity", Severity.MEDIUM)
            
            coverage_items.append(f'''
                <div class="coverage-item">
                    <div class="coverage-item-info">
                        <strong>{status_icon} {readable_name}</strong>
                        <span class="severity-badge {severity.value.lower()}">{severity.value}</span>
                    </div>
                    <div class="coverage-item-status">
                        <span class="status-badge {badge_class}">{status_text}</span>
                    </div>
                </div>
            ''')
        
        # Generate issues grouped by severity and type
        issues_html = []
        
        # First, add all severity sections
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if severity in by_severity:
                issues_html.append(f'<div id="severity-{severity.value.lower()}" class="section">')
                issues_html.append(f'<h3 class="{severity.value.lower()}">{severity.value} Severity Issues ({len(by_severity[severity])})</h3>')
                
                for issue in by_severity[severity]:
                    issue_id = f"issue-{severity.value.lower()}-{self.issues.index(issue)}"
                    issue_html = f"""
    <div class="issue" id="{issue_id}">
        <div class="issue-header">
            <h4 class="{issue.severity.value.lower()}">{issue.issue_type.replace('_', ' ').title()}</h4>
            <div class="issue-meta">
                <span>📁 {os.path.basename(issue.file_path)}</span>
                <span>📍 Line {issue.line_number}</span>
            </div>
        </div>
        <div class="issue-content">
            <p><strong>File:</strong> {issue.file_path}</p>
            <p><strong>Description:</strong> {issue.description}</p>
            <p><strong>Recommendation:</strong> {issue.recommendation}</p>
            <div class="code"><pre>{issue.code_snippet}</pre></div>
        </div>
    </div>
"""
                    issues_html.append(issue_html)
                
                issues_html.append('</div>')
        
        # Add sections for issue types (for navigation)
        issues_html.append('<div style="height: 0; overflow: hidden;">')
        for issue_type, issues in by_type.items():
            type_id = issue_type.replace('_', '-')
            issues_html.append(f'<div id="type-{type_id}"></div>')
        issues_html.append('</div>')
        
        # Add JavaScript to handle type navigation
        issues_html.append('''
<script>
// Override scrollToSection for type navigation
window.addEventListener('DOMContentLoaded', function() {
    const originalScrollToSection = window.scrollToSection;
    window.scrollToSection = function(id) {
        if (id.startsWith('type-')) {
            // For type navigation, find all issues of this type
            const typeName = id.replace('type-', '').replace(/-/g, '_');
            const issues = document.querySelectorAll('.issue');
            let firstFound = null;
            
            issues.forEach(issue => {
                const headerText = issue.querySelector('h4').textContent.toLowerCase();
                const typeText = typeName.replace(/_/g, ' ').toLowerCase();
                if (headerText.includes(typeText)) {
                    if (!firstFound) {
                        firstFound = issue;
                    }
                    issue.style.border = '2px solid #3498db';
                    setTimeout(() => {
                        issue.style.border = '1px solid #e9ecef';
                    }, 3000);
                }
            });
            
            if (firstFound) {
                firstFound.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
            
            // Update active nav
            document.querySelectorAll('.nav-link').forEach(link => {
                link.classList.remove('active');
            });
            const activeLink = document.querySelector(`[onclick*="${id}"]`);
            if (activeLink) {
                activeLink.classList.add('active');
            }
            
            return false;
        } else {
            return originalScrollToSection(id);
        }
    };
});
</script>
        ''')
        
        return html.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            files_scanned=self.files_scanned,
            patterns_count=len(self.patterns),
            severity_nav=''.join(severity_nav),
            type_nav=''.join(type_nav),
            summary_cards=''.join(summary_cards),
            coverage_report=''.join(coverage_items),
            issues=''.join(issues_html) if issues_html else '<p class="success">✅ No security issues found!</p>'
        )


def print_banner():
    """Print a nice banner"""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║            🛡️  C# OWASP Security Auditor  🛡️                  ║
    ║                                                               ║
    ║  Automated security scanning for C# applications              ║
    ║  Following OWASP Top 10 guidelines                            ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)


def main():
    """Main entry point"""
    print_banner()
    
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description='Audit C# code for security vulnerabilities following OWASP guidelines',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'directory',
        help='Path to the C# project directory to audit'
    )
    
    parser.add_argument(
        '--output-dir', '-o',
        default='.',
        help='Directory to save reports (default: current directory)'
    )
    
    parser.add_argument(
        '--format', '-f',
        choices=['all', 'console', 'html', 'json'],
        default='all',
        help='Output format (default: all)'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress console output (only save files)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed progress during scan'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Validate directory
    if not os.path.exists(args.directory):
        print(f"❌ Error: Directory '{args.directory}' does not exist!")
        sys.exit(1)
    
    if not os.path.isdir(args.directory):
        print(f"❌ Error: '{args.directory}' is not a directory!")
        sys.exit(1)
    
    # Create output directory if needed
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    # Initialize auditor
    print(f"\n📁 Scanning directory: {args.directory}")
    print("⏳ This may take a moment for large projects...\n")
    
    auditor = CSharpSecurityAuditor()
    
    # Count files to scan
    total_files = 0
    for root, dirs, files in os.walk(args.directory):
        dirs[:] = [d for d in dirs if d not in ['bin', 'obj', '.git', 'packages', 'node_modules']]
        total_files += sum(1 for f in files if any(f.endswith(ext) for ext in ['.cs', '.cshtml', '.aspx', '.config']))
    
    if args.verbose and not args.quiet:
        print(f"📊 Found {total_files} files to scan\n")
    
    # Perform audit
    try:
        issues = auditor.audit_directory(args.directory)
        
        if not issues:
            print("✅ Great news! No security issues found!")
            return
        
        # Generate timestamp for filenames
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Generate reports based on format
        if args.format in ['all', 'console'] and not args.quiet:
            print(auditor.generate_report("console"))
        
        if args.format in ['all', 'html']:
            html_file = output_dir / f"security_audit_{timestamp}.html"
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(auditor.generate_report("html"))
            print(f"\n📄 HTML report saved: {html_file}")
        
        if args.format in ['all', 'json']:
            json_file = output_dir / f"security_audit_{timestamp}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                f.write(auditor.generate_report("json"))
            print(f"📊 JSON report saved: {json_file}")
        
        # Print summary
        if not args.quiet:
            print(f"\n🔍 Scan complete! Found {len(issues)} security issues.")
            
            # Count by severity
            severity_counts = {}
            for issue in issues:
                severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1
            
            print("\nSummary by severity:")
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                if severity in severity_counts:
                    emoji = {
                        Severity.CRITICAL: "🚨",
                        Severity.HIGH: "⚠️",
                        Severity.MEDIUM: "⚡",
                        Severity.LOW: "💡",
                        Severity.INFO: "ℹ️"
                    }[severity]
                    print(f"  {emoji} {severity.value}: {severity_counts[severity]}")
            
            # Show top issues by type
            issue_types = {}
            for issue in issues:
                issue_types[issue.issue_type] = issue_types.get(issue.issue_type, 0) + 1
            
            print("\n📋 Most common issue types:")
            for issue_type, count in sorted(issue_types.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  - {issue_type.replace('_', ' ').title()}: {count}")
        
    except Exception as e:
        print(f"\n❌ Error during audit: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        print("Usage: python audit.py /path/to/your/csharp/project\n")
        print("For more options: python audit.py --help")
        sys.exit(0)
    
    main()
