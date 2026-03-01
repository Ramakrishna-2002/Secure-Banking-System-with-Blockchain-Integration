Secure Banking System with Blockchain Integration

📌 Project Overview
This project was developed as my MSc Dissertation at Technological University Dublin. It presents the design and implementation of a secure banking system that integrates blockchain technology and AES encryption to protect financial transactions and ensure data integrity.
The goal was to address real-world financial security challenges by combining cryptographic techniques with the tamper-proof nature of blockchain, creating a system where transactions are secure, verifiable and resistant to unauthorised modification.

🛠 Technologies & Tools Used

Python — Backend development and application logic
Solidity — Smart contract development for blockchain integration
AES Encryption — Symmetric encryption for securing sensitive financial data
Blockchain — Decentralised and tamper-proof transaction ledger
HTML — Frontend interface
VirtualEnv — Python virtual environment management


⚙️ System Architecture
The system is structured into three main components:

Frontend — User interface for interacting with the banking system
Backend — Python-based application logic handling user requests, authentication and transaction processing
Blockchain Layer — Solidity smart contracts deployed to manage and verify transactions in a decentralised manner


🔐 Security Implementation

AES Encryption — Applied to protect sensitive user and transaction data at rest and in transit
Blockchain Integration — Every transaction is recorded on a blockchain ledger, ensuring immutability and transparency
Smart Contracts — Solidity contracts automate and enforce transaction rules without the need for a central authority
Data Integrity — Any attempt to tamper with transaction records is detectable through blockchain verification


🔧 Implementation Steps

Environment Setup

Python virtual environment configured
Dependencies installed and blockchain environment initialised


Backend Development

Built core banking logic in Python
Implemented AES encryption for data protection


Smart Contract Development

Wrote and deployed Solidity smart contracts for transaction management
Tested contract execution and validation


Frontend Development

Built a basic HTML interface for user interaction with the banking system


Integration & Testing

Integrated all components and tested end-to-end transaction flow
Verified encryption, blockchain recording and data integrity


📊 Key Outcomes

Successfully implemented a fully functional secure banking prototype
Demonstrated that blockchain integration significantly enhances transaction integrity and auditability
AES encryption effectively protected sensitive financial data throughout the system
Identified practical challenges and limitations of blockchain adoption in real-world banking environments


🔍 Lessons Learned

Blockchain provides strong tamper-proof guarantees but requires careful design for performance at scale
AES encryption is highly effective for protecting data but key management is a critical consideration
Combining cryptographic and blockchain techniques offers a robust approach to financial system security


📂 Project Nature
This was an academic MSc dissertation project developed at Technological University Dublin. It is a prototype system built for research and educational purposes and was not deployed in any production environment.

📄 Documentation
The full dissertation report is available in this repository as a PDF.
