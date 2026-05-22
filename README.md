# MailDefender - Email Threat Analyzer

MailDefender is a lightweight, professional email analysis platform designed for SOC analysts to investigate phishing emails, extract IOCs, and assess risks.

## Features

- **Email File Upload**: Support for `.eml` files with MIME validation.
- **Header Analysis**: Deep dive into email headers including sender authenticity and relay chains.
- **Authentication Analysis**: Automated SPF, DKIM, and DMARC verification.
- **IOC Extraction**: Automatic extraction of URLs, IP addresses, domains, and email addresses.
- **Threat Scoring**: Weighted risk scoring engine with detailed reasoning.
- **Attachment Analysis**: Metadata extraction, hash generation (MD5, SHA1, SHA256), and suspicious file detection.
- **SOC Dashboard**: Professional interface for managing investigations.
- **Export Options**: Export Indicators of Compromise (IOCs) in JSON and CSV formats.

## Security

- **Safe Rendering**: All email body content is sanitized using `bleach` to prevent XSS.
- **Secure Handling**: Uploaded files are processed in memory or temporary storage and deleted immediately after analysis.
- **No Execution**: Attachments are analyzed for metadata only; no execution of macros or scripts occurs.

## Tech Stack

- **Backend**: Python 3, Flask, SQLAlchemy, SQLite
- **Frontend**: Bootstrap 5 (Dark Mode)
- **Key Libraries**: `mail-parser`, `beautifulsoup4`, `dnspython`, `tldextract`, `pyspf`, `dkimpy`, `bleach`

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd mail-defender
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python app.py
   ```

4. **Access the web interface**:
   Open your browser and navigate to `http://localhost:5000`

## Testing

Run the test suite using `pytest`:
```bash
export PYTHONPATH=$PYTHONPATH:.
pytest
```

## Project Structure

- `app/`: Main application package
  - `routes/`: Flask blueprints for web and API routes
  - `services/`: Business logic for parsing, auth, and threat analysis
  - `templates/`: Jinja2 HTML templates
  - `models.py`: Database models
- `tests/`: Unit and integration tests
- `config.py`: Application configuration
- `app.py`: Entry point
