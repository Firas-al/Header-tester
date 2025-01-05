# Header Tester

## Description
This script analyzes various security headers and certificates for websites to ensure they adhere to best practices. The headers and properties it checks include:

- **DNSsec**: Domain Name System Security Extensions.
- **HTTPS**: Secure HTTP connections.
- **HSTS**: HTTP Strict Transport Security.
- **X-Frame-Options**: Protects against clickjacking attacks.
- **X-Content-Type-Options**: Prevents MIME type sniffing.
- **Content-Security-Policy (CSP)**: Guards against cross-site scripting and other attacks.
- **Referrer-Policy**: Controls the information sent with requests.
- **Digital Certificate (X.509)**: Ensures the validity of the SSL/TLS certificate.

The results are exported to an Excel file for easy analysis.

This project is part of the research conducted for [this publication](https://lnu.diva-portal.org/smash/record.jsf?dswid=6479&pid=diva2%3A1701444&c=1&searchType=SIMPLE&language=sv&query=DNSsec%2B&af=%5B%5D&aq=%5B%5B%5D%5D&aq2=%5B%5B%5D%5D&aqe=%5B%5D&noOfRows=50&sortOrder=author_sort_asc&sortOrder2=title_sort_asc&onlyFullText=false&sf=all) at Linnaeus University.

---

## Features

- Reads a list of websites from `test.txt`.
- Checks and validates the following:
  - X-Frame-Options
  - X-Content-Type-Options
  - HSTS
  - CSP
  - HTTPS connection
  - DNSsec configuration
  - Referrer-Policy headers
  - Certificate revocation status (via OCSP)
  - SSL/TLS Certificate validity
- Outputs results to an Excel file named `results.xlsx`.

---

## Requirements

To run the script, you need the following Python libraries:

- `datetime`
- `socket`
- `ssl`
- `urllib`
- `dns`
- `requests`
- `xlsxwriter`
- `ocspchecker`

Install dependencies using pip:

```bash
pip install requests xlsxwriter dnspython ocspchecker
```

---

## File Structure

- **`test.txt`**: Contains the list of websites to analyze (one domain per line).
- **`results.xlsx`**: Generated Excel file with analysis results.
- **`header_tester.py`**: The main script file.

---

## How to Use

1. **Prepare the Input File:**
   Create a `test.txt` file containing the domains you want to analyze, one per line. For example:

   ```
   example.com
   google.com
   github.com
   ```

2. **Run the Script:**
   Execute the script using Python:

   ```bash
   python header_tester.py
   ```

3. **View the Results:**
   Open the `results.xlsx` file to see the analysis.

---

## Output

The script generates an Excel file (`results.xlsx`) with the following columns:

| Column | Description                       |
|--------|-----------------------------------|
| A      | Website                           |
| B      | X-Frame-Options Status           |
| C      | X-Content-Type-Options Status    |
| D      | HSTS Status                      |
| E      | Content-Security-Policy (CSP)    |
| F      | HTTPS Status                     |
| G      | DNSsec Status                    |
| H      | Referrer-Policy Headers Status   |
| I      | Certificate Revocation Status    |
| J      | X.509 Certificate Validity       |

---

## Example Output

A successful run will generate an Excel sheet with results for each domain, e.g.:

| Website       | X-Frame-Options | X-Content-Type-Options | HSTS | CSP | HTTPS | DNSsec | Referrer-Policy Headers | Revoked | X.509 |
|---------------|-----------------|-------------------------|------|-----|-------|--------|-------------------------|---------|-------|
| example.com   | Okay            | Okay                    | Okay | Okay| Okay  | Okay   | Okay                   | GOOD    | OK    |
| insecure.com  | Not Okay        | Not Okay                | No   | No  | Error | Error  | Not Okay               | Error   | Error |

---

## References

- [Stack Overflow - Handling Headers in Python](https://stackoverflow.com/questions/24533018/get-a-header-with-python-and-convert-in-json-requests-urllib2-json)
- [CSP Directives Explanation](https://stackoverflow.com/questions/55588079/csp-self-is-failing-in-various-directives)
- [OCSP Checker Documentation](https://github.com/OCSPChecker/ocspchecker)

---

## License
This project is open-source and distributed under the MIT License.

