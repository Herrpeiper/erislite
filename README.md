# ErisLITE

![Python](https://img.shields.io/badge/python-3.x-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-development-orange)

*A lightweight security monitoring and analysis toolkit.*

ErisLITE is a modular cybersecurity utility designed to assist analysts, students, and system administrators with basic system inspection, security auditing, and threat awareness tasks.

The tool provides a structured command-line interface and a collection of utilities that help users observe system state, review logs, and identify potential indicators of risk.

The project emphasizes **clarity, modularity, and accessibility**, making it useful for both learning environments and operational experimentation.

---

# Features

## Threat Sweep

Threat Sweep performs a series of system checks intended to highlight potential security concerns.

These checks may include:

- File integrity monitoring
- Suspicious network listeners
- World-writable file detection
- Cron / timer inspection
- Authentication or login anomalies
- System configuration review

Sweep results can be exported to logs for later analysis.

---

## Sweep Log Viewer

The Sweep Log Viewer provides an interface for reviewing Threat Sweep results.

Users can:

- View previous sweep results
- Inspect detailed reports
- Review associated risk scores
- Examine detection tags or indicators

This allows analysts to evaluate past system states and identify patterns in system behavior.

---

## Modular Architecture

ErisLITE is built around a modular architecture, allowing tools and functionality to be extended or replaced without rewriting the entire system.

Module categories may include:

- Core system utilities
- Security inspection tools
- Logging and analysis utilities
- CLI interface components

---

## Analyst-Oriented CLI

ErisLITE uses a structured command-line interface designed to provide a clear workflow for navigating modules and executing system checks.

The CLI is intended to function as a lightweight operational console rather than a collection of standalone scripts.

---

# Project Goals

ErisLITE was developed with several objectives:

- Provide a lightweight security inspection toolkit
- Offer a practical learning platform for cybersecurity students
- Support experimentation with modular defensive tools
- Allow analysts to quickly review system state and potential risk indicators

The project prioritizes **simplicity, transparency, and extensibility**.

---

# Installation

Clone the repository:

git clone https://github.com/herrpeiper/ErisLITE.git
cd ErisLITE

Install dependencies:
pip install -r requirements.txt

Run ErisLITE:
- sudo python3 main.py
- python3 main.py

---

# Usage
After launching ErisLITE, the CLI interface will present a menu system that allows access to the available modules.

Typical workflow:
1. Launch ErisLITE
2. Select Threat Sweep
3. Review generated findings
4. Open Sweep Log Viewer to review previous results

---

# Example Workflow

Run a Threat Sweep:
- python3 main.py

Navigate through the CLI and select the Threat Sweep module to perform a system scan.

After completion, the results will be logged and can be reviewed using the Sweep Log Viewer.

---

# Project Structure

Example directory layout:

ErisLITE/
│
├── core/                # Core system utilities
├── tools/               # Security tools and modules
├── ui/                  # CLI interface components
│
├── data/
│   └── logs/            # Threat Sweep logs and reports
│
├── main.py              # Program entry point
├── requirements.txt     # Python dependencies
└── README.md

---

# Development

ErisLITE is designed to support modular development. New tools can be added without modifying the entire application.

Recommended practices when extending the project:
- Follow the existing module structure
- Maintain consistent logging formats
- Document modules clearly
- Keep security checks modular and reusable

---

# License

This project is licensed under the MIT License.

See the LICENSE file for details.

---

# Author

Liam Piper-Brandon (Stackdefender)

---

# Disclaimer

This software is provided for educational and research purposes.

Users are responsible for ensuring that the software is used in compliance with applicable laws, system policies, and authorization requirements.