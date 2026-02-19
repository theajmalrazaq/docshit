# 📄 DocShit

**DocShit** is a high-performance, brutalist document analysis tool designed to sanitize PDF and DOCX files for secure LLM (Large Language Model) usage. It acts as a digital shield, identifying and neutralizing prompt injections, hidden text, and malicious metadata before they reach your AI context.

## 🛡️ Key Features

- **Multi-Format Deep Scan**: Support for both PDF and DOCX files with full structural analysis.
- **Threat Detection Engine**:
    - **Injection Keywords**: Identifies phrases used for prompt hijacking.
    - **Micro-Text Detection**: Catches microscopic text used to hide instructions from human eyes.
    - **Hidden Metadata**: Detects white-on-white text and other obfuscation techniques in DOCX files.
- **Safe Text Sanitization**: One-click extraction of "clean" text with malicious fragments neutralized.
- **Proofread Mode**: Side-by-side view of the original document and extracted text with pulsed highlighting on identified threats.
- **OCR Failure Detection**: Automatically identifies documents with no selectable text (handwritten/scanned images) and warns the user.
- **100% Client-Side**: Your documents never leave your browser. Processing is entirely local for maximum privacy.


## 🚀 Tech Stack

- **Core**: React + Vite
- **Styling**: Tailwind CSS + Framer Motion (Animations)
- **PDF Engine**: `pdfjs-dist`
- **DOCX Engine**: `jszip` + `docx-preview`
- **Visuals**: `lucide-react` (Icons) + `canvas-confetti` (FX)

## 🛠️ Usage

1. **Upload**: Drag and drop your PDF or DOCX file.
2. **Analyze**: Watch the real-time structure scan identify risks.
3. **Proofread**: Review detections in the highlight panel.
4. **Sanitize**: Copy the safe, neutralized text directly to your clipboard for LLM input.

---

*Built for the security-conscious explorer. Keep your AI context clean.*
