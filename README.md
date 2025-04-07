<h1 align="center">
<br>
<img src=/files/awesome-iguanas.jpg height="375" border="2px solid #000000">
<br>
Awesome Iguanas Vulnerability Detection Tool
</h1>


## WHAT

  `IguanaGPT` is a LLM online vulnerability detection tool that aims to fix software bugs using Large Language Models (LLMs). `IguanaGPT` utilizes a Neo4j CWE database in combination with Llama. This tool prioritizes ease-of-use for the casual programmer.

  As a proof of concept, `IguanaGPT` capabilities include:

  >  1. Dynamic solutions for memory safety vulnerabilities in any programming language.
  >  2. Constantly updating CWE database logic.
  >  3. User friendly online interface that prioritizes programmers of any skill level. 

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

## UTILITY SCRIPTS

The repository includes two powerful utility scripts that support the main functionality of IguanaGPT:

### 1. Language Identification Tool (`lan_identify.py`)

This script provides advanced language detection capabilities for code repositories and files. It helps determine which programming languages are used in a project, which is essential for proper vulnerability analysis.

**Key Features:**
- Multi-method language detection using both GitHub's Linguist and Python's Pygments
- Automatic dependency installation with platform-specific support (Windows/Linux)
- Interactive menu system for ease of use
- Comprehensive error handling and fallback mechanisms
- Percentage-based language breakdown for mixed-language repositories

**Usage:**
```
python lan_identify.py
```
Then follow the interactive menu to either detect languages in a folder or install dependencies.

### 2. OSV Database Updater (`osv_upload.py`)

This script fetches the latest vulnerability data from the Open Source Vulnerability (OSV) database and populates a Neo4j graph database for use by IguanaGPT. The script creates a comprehensive vulnerability graph with relationships between packages, CVEs, and references.

**Key Features:**
- Automated downloading of the OSV vulnerability database
- Smart filtering using a greedy algorithm to minimize database size while maximizing coverage
- Comprehensive Neo4j graph creation with multiple node types:
  - Vulnerability nodes (OSV entries)
  - Package nodes (affected software)
  - CVE nodes (related vulnerability identifiers)
  - Reference nodes (links to advisories, fixes)
- Rich relationship mapping between different node types

**Technical Details:**
- Configurable processing percentages for testing vs. production use
- Timeout handlers to prevent hanging on large operations
- Detailed progress monitoring with progress bars
- Comprehensive database statistics reporting

These utility scripts help maintain the backend infrastructure that powers IguanaGPT's vulnerability detection capabilities.

## FEATURES

- **Language Agnostic Detection**: Works with multiple programming languages
- **Interactive Visualization**: Neo4j-based graph visualization of vulnerability relationships
- **Customizable Security Rules**: Adjust sensitivity based on project requirements
- **Detailed Reporting**: Comprehensive vulnerability reports with remediation suggestions
- **API Integration**: Connect with your CI/CD pipeline for automated scanning

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
- [Alexander James](https://github.com/Pacificocean1912)
- [Matthew Trevino](https://github.com/MattjTrev)

**Documentation Updates:**
- [Samantha Jackson](https://github.com/Erosssore)

## LICENSE
This project is licensed under the Apache License Version 2.0 - see the [LICENSE](LICENSE) file for details.
