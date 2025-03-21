# Spoof Checker

![Email Authentication Scanner](https://img.shields.io/badge/Email-Authentication_Scanner-blue)
![Python](https://img.shields.io/badge/Python-3.6+-brightgreen)
![License](https://img.shields.io/badge/License-MIT-orange)

A powerful subdomain email authentication scanner that helps identify domains vulnerable to email spoofing.

</p>
<p align="center">
  <img src="https://github.com/pentestfunctions/spoof_checker/blob/main/images/example_email.gif">
</p>

## 🔍 Overview

Spoof Checker automatically discovers subdomains for a target domain and analyzes their email security configurations, identifying those that could be vulnerable to email spoofing attacks. The tool checks for SPF, DKIM, and DMARC records, evaluates risk levels, and provides actionable verification commands.

## ✨ Features

- **Subdomain Discovery** - Uses Web Archive to find subdomains of your target
- **Complete Email Security Analysis** - Checks for SPF, DKIM, and DMARC records
- **Risk Assessment** - Categorizes domains by risk level (protected, moderate, high)
- **MX Record Verification** - Identifies domains with active mail servers
- **Multi-threaded Scanning** - Fast and efficient checking of multiple domains
- **Rich Terminal Output** - Color-coded results and clear risk indicators
- **Verification Commands** - Provides commands to verify findings
- **Remediation Guidance** - Offers suggestions to improve email security posture

## 📋 Requirements

- Python 3.6+
- Required packages:
  - requests
  - dnspython
  - rich

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/pentestfunctions/spoof_checker.git
cd spoof_checker

# Install dependencies
pip install -r requirements.txt
```

## 📊 Usage

Basic usage:

```bash
python3 emailspoofchecking.py example.com
```

With custom recipient for examples:

```bash
python3 emailspoofchecking.py example.com -r your@email.com
```

## 📋 Output Example

The tool provides a comprehensive table showing:

- List of discovered subdomains
- Each domain's security status (Protected, Moderate Risk, High Risk, Spoofable)
- SPF, DKIM, and DMARC record status
- MX record presence
- Specific commands to verify vulnerabilities
- Examples of how spoofing could be attempted (for educational purposes)

## 🔒 Security Risk Levels

- **Protected** - Has proper SPF, DKIM, and DMARC records, or no mail servers
- **Moderate Risk** - Has SPF and DMARC, but missing DKIM
- **High Risk** - Has mail servers but missing SPF or DMARC records
- **Spoofable** - Practically exploitable due to severe configuration issues

## 🛡️ Defensive Recommendations

The tool provides specific recommendations for each risk level:

- **High Risk Domains**: Implement both SPF and DMARC records immediately
- **Moderate Risk Domains**: Add DKIM authentication to complete email security profile
- **All Domains**: Regularly monitor and test email authentication configurations

# ProtonMail Email Authentication Warning Behavior

## When You Might See a Warning Message

### Scenario 1: Main Inbox with Potential Warning
- **Authentication Status**: Valid SPF, Missing DKIM, Missing DMARC
- **Result**: Email appears in the main inbox, sometimes with warning message
- **Warning Text**: 
  > This email has failed its domain's authentication requirements. It may be spoofed or improperly forwarded. [Learn more]

*Note: This warning appears inconsistently - most times you won't see it despite the missing authentication elements.*

### Scenario 2: Spam Folder with Warning
- **Authentication Status**: Valid SPF, Missing DKIM, Valid DMARC
- **Result**: Email is placed in spam folder with warning message
- **Warning Text**:
  > This email has failed its domain's authentication requirements. It may be spoofed or improperly forwarded. [Learn more]

## Understanding Email Authentication Elements

| Element | Purpose | Status Impact |
|---------|---------|---------------|
| **SPF** | Verifies sender's IP is authorized to send from that domain | Valid SPF helps but isn't sufficient alone |
| **DKIM** | Cryptographically verifies email integrity and authenticity | Missing DKIM triggers warnings |
| **DMARC** | Defines domain policy for authentication failures | Valid DMARC without DKIM can route to spam |

## Key Takeaways

1. For best deliverability, implement all three authentication methods
2. Missing DKIM is particularly problematic for ProtonMail filtering
3. Having valid DMARC without valid DKIM can actually worsen delivery (sends to spam)
4. Warning messages appear inconsistently in the first scenario

---

Made with ❤️ by [pentestfunctions](https://github.com/pentestfunctions)
