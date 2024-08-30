# Encryptica

Encryptica is a Python-based encryption and decryption tool that supports multiple encryption algorithms. The tool can randomly choose an encryption method for each character in a given text, making it difficult to crack without knowing the specific pattern and algorithm used.

## Features

- **Caesar Cipher**
- **Vigenere Cipher**
- **RSA Encryption**
- **DES Encryption**
- **Blowfish Encryption**

## Prerequisites

Before running Encryptica, ensure you have the following installed:

- Python 3.6+
- Required Python packages (can be installed via `requirements.txt`)

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/YourUsername/Encryptica.git
    ```

2. Navigate to the project directory:

    ```bash
    cd Encryptica
    ```

3. (Optional) Create and activate a virtual environment:

    ```bash
    python -m venv venv
    source venv/bin/activate   # On Windows use `venv\Scripts\activate`
    ```

4. Install the required Python packages:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Running Encryptica

To run Encryptica, simply execute the `encryptica.py` script:

```bash
python encryptica.py
