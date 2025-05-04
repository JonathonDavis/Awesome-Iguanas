<h1 align="center">
<br>
<img src=/files/awesome-iguanas.jpg height="400" border="2px solid #000000">
<br>
Awesome Iguanas Vulnerability Detection Tool
</h1>


## WHAT

  `IguanaGPT` is an LLM online vulnerability detection tool that aims to fix software bugs using large language models (LLMs). It utilizes a Neo4j CVE database in  combination with Deepseek R1:8B.

  As proof of concept, `IguanaGPT` capabilities include:

  >  1. Dynamic identification of memory safety vulnerabilities in any programming language.
  >  2. Constantly updating the CWE database logic.
  >  3. User-friendly online interface with detailed database analysis. 

## HOW TO USE

  `IguanaGPT` utilizes a Vue.js-based frontend, which can be accessed through our web interface. For local development:

  1. Clone this repository
  2. Navigate to the `frontend` directory
  3. Run `npm install` to install dependencies
  4. Run `npm run dev` to start the development server
  5. Access the application at `http://localhost:5173` (or the port shown in your terminal)

  For more information on Vue.js, visit: <i>https://vuejs.org/guide/quick-start</i>

## METHODOLOGY

The methodology behind `IguanaGPT` involves the following steps:

1. **Data Collection**: 
   - Leverages a Neo4j graph database populated with the latest CWE (Common Weakness Enumeration) data from [OSV](https://osv.dev/)
   - Regular updates ensure the database remains current with emerging vulnerabilities
   - Correlates vulnerability patterns across different programming languages and frameworks

2. **LLM Integration**:
   - Utilizes DeepseekR1:8B to analyze and detect vulnerabilities in code
   - Fine-tuned specifically for code analysis and vulnerability detection
   - Implements prompt engineering to optimize model responses for security contexts

3. **Dynamic Analysis**:
   - Performs real-time analysis of CVE vulnerabilities
   - Generates tailored solutions based on the context and programming language
   - Prioritizes fixes for high-risk vulnerabilities according to CVSS scoring

4. **User Interface**:
   - Provides an intuitive Vue.js-based web interface with database analysis features
   - Features a responsive design that works across desktop and mobile devices

5. **Feedback Loop**:
   - Incorporates user feedback to improve the accuracy and relevance of the tool's suggestions
   - Continuously refines the LLM and database logic for better results
   - Implements versioning to track the effectiveness of vulnerability detection over time

Combining cutting-edge AI technology with an up-to-date vulnerability database, `IguanaGPT` aims to streamline the identification and addressing of software vulnerabilities.

## UTILITY SCRIPT(S)

The repository contains three powerful utility scripts that support the main functionality of `IguanaGPT`:

### 1. Database Handler (`VulGPT_OSV/TestOSVGIT3.py`)

This file handles the bulk of the backend with continuous OSV Database scraping integration, Neo4J compatibility and ingestion via Bolt, and frontend integration.

#### Key Features:
- Automated download and update handling from the [Open Source Vulnerability Database](https://osv.dev/)
- Smart filtering using a [greedy algorithm](https://en.wikipedia.org/wiki/Greedy_algorithm) for efficiency
- Comprehensive Neo4j graph creation with multiple node types:
  - Vulnerability nodes (OSV entries)
    - id: <i>Vulnerability ID</i>
    - schema_version, published, modified, summary, details
    - severity: <i>JSON severity string</i>
    - affected: <i>JSON string of affected packages</i>
    - database_specific: <i>JSON blob</i>
  - Package nodes (affected software)
    - name: <i>Package name</i>
    - ecosystem: <i>ecosystem types (go, npm, PyPI, etc.)</i>
  - Repository nodes (GitHub repositories containing vulnerable code)
    - url: <i>GitHub repository URL</i>
  - Version nodes (with language statistics and version strings)
    - id: <i>Unique version ID</i>
    - version: <i>Version string</i>
    - size: <i>Disk size of the repository file</i>
    - language_json: <i>Full language breakdown</i>
    - primary_languag: <i>Most dominant language in the repository</i>
    - language_count: <i>Number of dedicated languages</i>
  - CVE nodes (related vulnerability identifiers)
    - ID: <i>CVE ID Linked to the Vulnerability (CVE-2025-12345)</i>
  - Reference nodes (links to advisories, fixes)
    - url: <i>URL to Notice</i>
    - type: <i>Optional (ex. ADVISORY, FIX, etc.)</i>
- Relationship mapping between nodes using Cypher query logic
    - AFFECTED_BY: <i>Package -> Vulnerability (Packages affected by this vulnerability)</i>
    - IDENTIFIED_AS: <i>CVE -> Vulnerability (CVE ID for the vulnerability)</i>
    - REFERS_TO: <i>Vulnerability -> Reference (External links or vulnerability advisories)</i>
    - FOUND_IN: <i>Vulnerability -> Repository (The vulnerabilities existing in this GitHub repository)</i>
    - HAS_VERSION: <i>Repository -> Version (GitHub repository versions/tags)</i>
    - RELATED_TO: <i>Vulnerability -> Vulnerability (Similar vulnerabilities)</i>

#### Technical Details:
- Configurable processing percentages for testing and production use
- Timeout handlers to prevent hanging on large operations
- Error handling for:
  - OSV Data downloading and processing
  - GitHub repository cloning retry logic
  - Linguist fallbacks for manual language detection
  - Neo4j insertion error handling
  - Main script crash prevention
  - Repeat node correction for continuous updates
- Comprehensive database statistics reporting

This utility script helps maintain the backend infrastructure that powers `IguanaGPT` vulnerability detection capabilities.

### 2. Update Timestamps (`VulGPT_OSV/daily_osv_update.sh`)

This shell script logs the node updates for Neo4J. It will run when `daily_osv_update.sh` is executed.

#### Technical Details:
- This file dynamically logs node updates in Neo4J, allowing for easy troubleshooting and error logging
- When completed, this script closes its connection with Neo4J

This timestamp script allows us to maintain a detailed log of Neo4J infrastructure updates.

### 3. Daily Update Script (`VulGPT_OSV/daily_osv_update.sh`)

This shell script handles updating the nodes in Neo4J. It is linked to a cron job scheduled to run at `3:00 AM GMT Daily`

#### Technical Details:
- This file will trigger a cron job at `3:00 AM GMT Daily` within the VM handling this Neo4J database
- This file is set to run the update script `TestOSVGIT3.py` first, then `update_tracking_timestamp.py`
  - `TestOSVGIT3.py` for updating purposes
  - `update_tracking_timestamp.py` for logging purposes
- Error handling for missing file locations
- Confirmation of completion when updates are completed to the console

This shell script helps maintain the updated structure of the scripts.

## FEATURES

- <b>Language Agnostic Detection</b>: Works with multiple programming languages
- <b>Interactive Visualization</b>: Neo4j-based graph visualization of vulnerability relationships

## MILESTONES VIDEO REPORTS
<h2 align="center">Milestone 1 </h2>
<p align="center">
  <a href="https://youtu.be/vUtb4zwUBao?si=1ftEJPqavI6z_9yC">
    <img src="files/IguanasMilestone1.png" alt="Milestone 1" width="720">
  </a>
</p>

<h2 align="center">Milestone 2</h2>
<p align="center">
  <a href="https://youtu.be/yfaaWXrq3rI?si=1sgcpeTci_-ZG_zJ">
    <img src="files/IguanasMilestone2.png" alt="Milestone 2" width="720">
  </a>
</p>

## DISCLAIMER

> This tool is for testing and academic purposes; all responses from IguanaGPT should NOT be considered axioms.
> LLM scores can vary in quality even on a session-to-session basis. Using this tool 
> as your only benchmark for software quality can have serious consequences. The
> end user are responsible for ensuring that their programs are adequately tested for quality assurance.
> Developers assume no liability and are not responsible for any damage caused by this tool and software.

## CREDIT

**Project Lead:** 
- [Matthew Trevino](https://github.com/MattjTrev)

**Frontend Developers:** 
- [Jonathon Davis](https://github.com/JonathanDavis)

**Backend Developers:** 
- [Matthew Trevino](https://github.com/MattjTrev)
- [Joshua Ludolf](https://github.com/Joshua-Ludolf)

**LLM Developer**
- [Alexander James](https://github.com/pacificocean1912)

**Documentation Updates:**
- [Samantha Jackson](https://github.com/Erosssore)

**Team Member**
- [Yesmin Hernandez](https://github.com/Yesmin301)
## LICENSE
This project is licensed under the Apache License Version 2.0 - see the [LICENSE](LICENSE) file for details.
