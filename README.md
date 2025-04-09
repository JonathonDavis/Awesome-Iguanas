<h1 align="center">
<br>
<img src=/files/awesome-iguanas.jpg height="400" border="2px solid #000000">
<br>
Awesome Iguanas Vulnerability Detection Tool
</h1>


## WHAT

  `IguanaGPT` is a LLM online vulnerability detection tool that aims to fix software bugs using Large Language Models (LLMs). `IguanaGPT` utilizes a Neo4j CWE database in  combination with Llama. This tool prioritizes ease-of-use for the casual programmer.

  As a proof of concept, `IguanaGPT` capabilities include:

  >  1. Dynamic solutions for memory safety vulnerabilities in any programming language.
  >  2. Constantly updating CWE database logic.
  >  3. User-friendly online interface that prioritizes programmers of any skill level. 

## HOW TO USE

  `IguanaGPT` utilizes a Vue.js-based frontend which can be accessed through our web interface. For local development:

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
   - Utilizes Llama to analyze and detect vulnerabilities in code
   - Fine-tuned specifically for code analysis and vulnerability detection
   - Implements prompt engineering to optimize model responses for security contexts

3. **Dynamic Analysis**:
   - Performs real-time analysis of user-provided code snippets
   - Generates tailored solutions based on the context and programming language
   - Prioritizes fixes for high-risk vulnerabilities according to CVSS scoring

4. **User Interface**:
   - Provides an intuitive Vue.js-based web interface for users to upload code and receive feedback
   - Features responsive design that works across desktop and mobile devices
   - Designed to accommodate users of all skill levels, from beginners to advanced programmers

5. **Feedback Loop**:
   - Incorporates user feedback to improve the accuracy and relevance of the tool's suggestions
   - Continuously refines the LLM and database logic for better results
   - Implements versioning to track effectiveness of vulnerability detection over time

By combining cutting-edge AI technology with an up-to-date vulnerability database, `IguanaGPT` aims to streamline the process of identifying and addressing software vulnerabilities.

## UTILITY SCRIPT(S)

The repository three powerful utility scripts that support the main functionality of `IguanaGPT`:

### 1. Database Handler (`VulGPT_OSV/TestOSVGIT3.py`)

This file handles the bulk of the backend with continuous OSV Database scraping integration, Neo4J compatibility and ingestion via Bolt, and frontend integration.

#### Key Features:
- Automated download and update handling from the [Open Source Vulnerability Database](https://osv.dev/)
- Smart filtering using a [greedy algorithm](https://en.wikipedia.org/wiki/Greedy_algorithm) for efficiency
- Comprehensive Neo4j graph creation with multiple node types:
  - Vulnerability nodes (OSV entries)
    - id: <i>Vulnerability ID</i>
    - schema_version, published, modiifed, summary, details
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

This shell script handles logging the node updates for Neo4J. This will run when `daily_osv_update.sh` is executed.

#### Technical Details:
- This file dynamically logs node updates in Neo4J allowing for easy troubleshooting and error logging
- When completed this script closes its connection with Neo4J

This timestamp script allows us to maintain a detailed log of Neo4J infrastructure updates.

### 3. Daily Update Script (`VulGPT_OSV/daily_osv_update.sh`)

This shell script handles updating the nodes in Neo4J. It is linked to a cron job scheduled to run at `3:00 AM GMT Daily`

#### Technical Details:
- This file will trigger a cron job at `3:00 AM GMT Daily` within the VM handling this Neo4J database
- This file is set to run the update script `TestOSVGIT3.py` first then `update_tracking_timestamp.py`
  - `TestOSVGIT3.py` for updating purposes
  - `update_tracking_timestamp.py` logging purposes
- Error handling for missing file locations
- Confirmation of completion when updates are completed to the console

This shell script helps maintain the update structure of the scripts.

## FEATURES

- <b>Language Agnostic Detection</b>: Works with multiple programming languages
- <b>Interactive Visualization</b>: Neo4j-based graph visualization of vulnerability relationships
- TODO: <b>Customizable Security Rules</b>: Adjust sensitivity based on project requirements
- TODO: <b>Detailed Reporting</b>: Comprehensive vulnerability reports with remediation suggestions

## MILESTONES
<h2 align="center"> Milestone 1 </h2>
<h3 align="center">
    <video width="720" height="405" controls style="display: block; margin:0 auto">
        <source src="/files/Milestone1.mp4" type="video/mp4">
    </video>
</h3>

<h2 align="center"> Milestone 2 </h2>
<h3 align="center">
    <br>
    <video width="720" height="405" controls>
        <source src="/files/Milestone2-ffmpeg.mp4" type="video/mp4">
    </video>
    <br>
</h3>

## DISCLAIMER

> This tool is for testing and academic purposes all responses from IguanaGPT should NOT be considered axioms.
> LLM scores can vary in quality even on a session to session basis. Using this tool 
> as your only benchmark for software quality can have serious consequences. It is the
> end users responsibility to ensure that their programs are adequately tested for quality assurance.
> Developers assume no liability and are not responsible for any damage caused by this tool and software.

## CREDIT

**Project Lead:** 
- [Matthew Trevino](https://github.com/MattjTrev)

**Frontend Developers:** 
- [Jonathon Davis](https://github.com/JonathanDavis)
- [Yesmin Hernandez](https://github.com/Yesmin301)

**Backend Developers:** 
- [Joshua Ludolf](https://github.com/Joshua-Ludolf)
- [Matthew Trevino](https://github.com/MattjTrev)
- [Alexander James](https://github.com/pacificocean1912)

**Documentation Updates:**
- [Samantha Jackson](https://github.com/Erosssore)

## LICENSE
This project is licensed under the Apache License Version 2.0 - see the [LICENSE](LICENSE) file for details.
