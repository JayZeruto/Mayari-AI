# Mayari-AI
A localized, Strict Logics AI assistant focused on technical literacy, Educational tutoring, and secure automation.
# 🌙 Mayari AI (The Universal Literacy & Automation Assistant)

> **Mayari** (Philippine goddess of the Moon) represents a "guiding light" through complex technical and educational information.

## 🛡️ Security Features
Mayari AI implements comprehensive security measures to protect against various cyber threats:

### 🔒 Core Security Components
* **Input Validation & Sanitization:** Prevents XSS, injection attacks, and malicious content
* **Rate Limiting:** Protects against DDoS and abuse attempts
* **Encryption:** AES-256 encryption for sensitive data using Fernet
* **Authentication:** Secure password hashing with PBKDF2
* **Logging & Monitoring:** Comprehensive security event logging and alerting
* **Pattern Detection:** Advanced regex patterns to detect jailbreak attempts and malware requests

### 🚨 Security Protections
* Blocks prompt injection and jailbreak attempts
* Prevents execution of dangerous commands
* Sanitizes HTML and script content
* Implements secure error handling to prevent information leakage
* Uses cryptographically secure random number generation

### 🔧 Security Configuration
Security settings can be configured via environment variables:
- `MAYARI_ENCRYPTION_KEY`: Base64-encoded encryption key
- Rate limits and other settings configurable in `SecurityConfig`

### 📋 Dependencies
See `requirements.txt` for security-related dependencies. All dependencies are kept minimal and regularly audited for vulnerabilities.

## 🛠️ Technical Foundation & Compliance
* **Technical Translation:** Converts complex system errors into plain language for non-technical users.
* **Secure Logic Core:** Built on verified data to prevent hallucinations and malicious content generation.
* **Adaptive Tutoring:** Fact-based learning in Science, Law, and the Arts, tailored for users ages 4-65.
* **Privacy-First:** Designed as a localized Windows service to ensure data remains with the user.

## 🛠️ Technical Foundation & Compliance
* **Platform:** Windows (Background Service) / Future Containerization (Docker).
* **Inspiration:** J.A.R.V.I.S (Iron Man) & Bagley (Watch Dogs).
* **Compliance Research:** Researched via Google Gemini sandbox to align with U.S. AI regulations and ethical standards.

## 📊 Market Context
* **Integrity:** Like *Perplexity AI*, Mayari prioritizes cited, factual sources.
* **Integration:** Like *Microsoft Copilot*, it focuses on OS-level task automation.

## 🔬 Research & Development
Mayari AI is grounded in ongoing research across multiple domains:

### Educational AI Research
* Investigation into adaptive learning systems and personalized educational approaches
* Study of cognitive load theory to optimize information presentation
* Research on effective technical explanation methods for diverse age groups (4-65)

### Security Research
* Analysis of emerging AI security threats and mitigation strategies
* Study of prompt injection vulnerabilities and defense mechanisms
* Evaluation of encryption standards and authentication protocols

### AI Ethics & Compliance
* Research alignment with U.S. AI regulations and industry standards
* Investigation of AI bias detection and mitigation techniques
* Study of privacy-preserving machine learning approaches

### Technical Integration
* Windows service architecture optimization for background processes
* Research into containerization best practices for secure deployment
* Integration patterns for OS-level task automation

### Data Verification
* Development of fact-checking mechanisms to prevent hallucinations
* Research into knowledge verification from cited, authoritative sources
* Implementation of source attribution and citation tracking systems

### Future Research Areas
* Natural language processing improvements for technical translation
* Multilingual support expansion beyond English
* Advanced pattern recognition for detecting sophisticated attack vectors
* Machine learning optimization for local, edge-based processing
