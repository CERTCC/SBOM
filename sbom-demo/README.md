#SBOM demo tool
The SBOM demo tool was created to pursue use cases of build multi-lingual basic SBOM for
effort such as the [SBOM PoC effort](https://www.ntia.gov/files/ntia/publications/ntia_sbom_healthcare_poc_report_2019_1001.pdf).

The tool has a very simple template for multi-tier SBOM to be generated. The SBOM's generated in
[SPDX](https://spdx.org),
[SWID](https://nvd.nist.gov/products/swid) [ISO/IEC 19770](https://www.iso.org/standard/65666.html) and [CycloneDX](https://cyclonedx.org/) format are NOT production ready but basic to provide information that
can be gathered on software products that assemble other software.
The tool also generates a simple tree graph to visually verify the SBOM's structure. Vulnerabilities can be simulated on this tree structure.

You can visit [https://sbom.democert.org/sbom/](https://sbom.democert.org/sbom/) and run the Example to see how it works.

#Data collection and privacy

None of the data you enter or simulate is sent back to the server.  The data sits on the client-side.  The tools to generate SPDX, SWID and CycloneDX can all work even if your browser is disconnected from the network after loading the website.

#Looking for SBOM for this software ?
Look in self-sbom, currently has no assertions or hash signatures
