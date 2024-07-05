# The Shark Hunter

the shark hunter is a powerful and easy-to-use tool designed to simplify and enhance your workflow.

[![License: EPL-2.0](https://img.shields.io/badge/License-EPL%202.0-blue.svg)](https://opensource.org/licenses/EPL-2.0)
[![Documentation Status](https://readthedocs.org/projects/awesomeproject/badge/?version=latest)](https://thesharkhunter.rtfd.io)

![AwesomeProject Banner](/images/banner.png)

## Table of Contents
1. [Introduction](#introduction)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Contributing](#contributing)
6. [License](#license)
7. [Contact](#contact)

## Introduction
**the shark hunter helps cybersecurity and network analyst to Find malware and suspicious anomalies in packet files.**

## Features
- **Automation**: Automate repetitive tasks to save time.
- **Open Source**: Community-driven and open for contributions.

## Installation

### Prerequisites
- Python 3.8+
- pip
- Npcap
- wireshark + tshark (optional)

### Steps
### Windows
1. Clone the repository:
    ```bash
    git clone https://github.com/username/the-Shark-Hunter.git
    ```
2. Navigate to the project directory:
    ```bash
    cd the-Shark-Hunter
    ```
3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```
4. Edit the **config.py** and put your VirusTotal **Api_key**.
## Usage
1. Run the main application (h-shark.py) as Administrator :
    ```python
    python h-shark.py
    ```
2. Follow the on-screen instructions to utilize the features of the-shark-hunter.

### Example
```bash
python h-shark.py -r trickbot.pcap --scan
```
# Contributing

### Contributing to the Shark Hunter
Thank you for considering contributing to the Shark Hunter! We welcome contributions from everyone. By participating in this project, you agree to abide by our Code of Conduct.

## How Can I Contribute?
### Reporting Bugs
If you find a bug, please report it by creating a new issue on our GitHub Issues page. When reporting a bug, please include:

- A clear and descriptive title.
- A detailed description of the issue.
- Steps to reproduce the issue.
- Any relevant logs, screenshots, or other information.
### Suggesting Features
We welcome suggestions for new features. To suggest a feature, please create a new issue on our GitHub Issues page and include:

- A clear and descriptive title.
- A detailed description of the feature.
- Any relevant examples or use cases.
### Submitting Pull Requests
We welcome contributions in the form of pull requests (PRs). To submit a PR, please follow these steps:

1. **Fork the repository**: Click the "Fork" button at the top right corner of the repository page.
2. **Clone your fork**:
    ```bash
    git clone https://github.com/your-username/the-Shark-Hunter.git
    ```
3. **Create a new branch**:
    ```bash
    git checkout -b feature-branch-name
    ```
4. **Make your changes**: Implement your feature or bug fix.
5. **Commit your changes**:
    ```bash
    git commit -m "Description of your changes"
    ```
6. **Push to your fork**:
    ```bash
    git push origin feature-branch-name
    ```
7. **Create a pull request**: Go to the original repository and click the "New pull request" button. Provide a clear and descriptive title and description for your PR.
### Code Style
Please ensure your code follows our coding style guidelines:
- Use meaningful variable and function names.
- Maintain consistent indentation.
- Write comments where necessary to explain your code.
### Running Tests
Before submitting your pull request, make sure to run the existing tests to ensure your changes do not break anything. You can run the tests using:
```python
python -m unittest discover
```
### Documentation
If your changes affect the project's usage or features, please update the relevant documentation. This can include:
-Updating the README.md file.
-Adding or modifying docstrings in the code.
-Updating or creating additional documentation files.
### Code of Conduct
Please note that this project is released with a Contributor Code of Conduct. By participating in this project, you agree to abide by its terms.

### Getting Help
If you need any help or have questions, feel free to reach out by creating an issue or contacting the project maintainers.

Thank you for your contributions!

## License
This project is licensed under the Eclipse Public License 2.0 - see the LICENSE file for details.

## Contact
For any questions or suggestions, please contact us at rafiklg47@gmail.com.
