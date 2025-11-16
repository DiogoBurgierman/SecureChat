# LaTeX Report Documentation

This directory contains LaTeX source files for generating professional reports in LNCS (Lecture Notes in Computer Science) format.

## Files

- **`report.tex`** - Main technical report covering:
  - Introduction and threat model
  - Secure Chat Protocol (4 phases)
  - System Requirements and Implementation
  - Testing and Evidence
  - Certificate Inspection Results
  - Security Analysis
  - Conclusion

- **`test_report.tex`** - Test report covering:
  - Automated test suite results
  - Manual security tests
  - Non-repudiation verification
  - Test execution environment

## Compilation

### Prerequisites

Install LaTeX distribution:
- **Windows:** MiKTeX or TeX Live
- **Linux:** `sudo apt-get install texlive-latex-base texlive-latex-extra`
- **macOS:** MacTeX

### Compile Reports

```bash
# Compile main report
pdflatex report.tex
bibtex report
pdflatex report.tex
pdflatex report.tex

# Compile test report
pdflatex test_report.tex
bibtex test_report
pdflatex test_report.tex
pdflatex test_report.tex
```

Or use the provided script:
```bash
# Linux/Mac
./compile_reports.sh

# Windows
compile_reports.bat
```

## Output

Compilation produces:
- `report.pdf` - Main technical report
- `test_report.pdf` - Test report

These PDFs can be converted to DOCX format for submission if required.

## Student Information

- **Name:** Umer Farooq
- **Roll No:** 22I-0891
- **Section:** CS-7D
- **Instructor:** Urooj Ghani
- **Course:** Information Security (CS-3002)
- **Institution:** FAST--NUCES
- **Semester:** Fall 2025

## Notes

- Reports use LNCS format (Springer's Lecture Notes in Computer Science)
- All test results are included from `reports/automatic_tests_20251116_214240.json`
- Reports are ready for academic submission

