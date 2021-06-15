# Common Platform Enumeration (CPE) lookup example

NIST provides a [CPE database](https://nvd.nist.gov/products/cpe) that can be used to corelate information from CPE to find Common Vulnerabilities and Exposure (CVE) vulnerbalities for specific version of products from identified vendors.  The CPE database has just an example of enumerating vendor Microsoft with their products that have been identified with vulnerabilities using CVE.

The sample CPE association can be used in SBOM to identify product using CPE's dictionary.  The directories product_lookup and cve_lookup have a list of CVE identified vulnerabilities for the example microsoft vendor. As a Proof of Concept (PoC) effort this only attempts to simulate a limited vulnerability identification and association using SBOM. 
