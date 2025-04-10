# DataVault Pro

DataVault Pro is a professional Database Vulnerability Management System that helps organizations identify, track, and remediate software vulnerabilities efficiently. The system uses Neo4j graph database to store and analyze complex vulnerability relationships.

![DataVault Pro](https://via.placeholder.com/1200x600/1a2942/FFFFFF?text=DataVault+Pro)

## Overview

DataVault Pro provides a comprehensive solution for tracking vulnerabilities across your software ecosystem. Built with Vue 3 and Neo4j, it offers powerful visualization tools, detailed analytics, and an intuitive user interface for security professionals.

## Key Features

- **Vulnerability Management**: Track and manage vulnerabilities with detailed information including severity, affected packages, and remediation status
- **Graph-Based Visualization**: Explore the relationships between vulnerabilities and affected packages
- **Advanced Analytics**: Gain insights into your security posture with comprehensive analytics dashboards
- **Responsive Design**: Access the platform from any device with a fully responsive interface

## Tech Stack

- **Frontend**: Vue 3, Vue Router, Chart.js, D3.js
- **Database**: Neo4j Graph Database
- **API**: RESTful services built with Node.js
- **Build Tools**: Vite, npm

## Folder Structure

- **`index.html`**: The entry point for the application.
- **`package.json`**: Dependencies and scripts for the project.
- **`vite.config.js`**: Configuration for Vite.
- **`src/`**: Main source folder.
  - **`App.vue`**: Root Vue component with main layout.
  - **`main.js`**: Entry point that initializes the Vue app.
  - **`style.css`**: Global styles.
  - **`assets/`**: Static assets like images and icons.
  - **`components/`**: Reusable Vue components.
  - **`data/`**: Data files used in the application.
  - **`router/`**: Routing configuration.
  - **`services/`**: Services for API and database interactions.
    - **`neo4j/`**: Neo4j database services.
      - **`neo4jService.js`**: Core service for database connectivity.
      - **`vulnerabilityProcessor.js`**: Handles vulnerability data processing.
      - **`statisticsService.js`**: Generates analytics and statistics.
      - **`repositoryService.js`**: Manages repository data.
  - **`views/`**: Main pages of the application.
    - **`Home.vue`**: Dashboard view.
    - **`Stats.vue`**: Analytics view.
    - **`Graphs.vue`**: Network visualization view.
    - **`About.vue`**: Documentation view.

## Getting Started

### Prerequisites

- Node.js 16+
- npm or yarn
- Neo4j Database (local or remote)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/JonathonDavis/Awesome-Iguanas
   cd Awesome-Iguanas/frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables:
   Create a `.env` file with the following settings:
   ```
   VITE_NEO4J_URI=neo4j://localhost:7687
   VITE_NEO4J_USER=neo4j
   VITE_NEO4J_PASSWORD=your-password
   ```

4. Start the development server:
   ```bash
   npm run dev
   ```

5. Open your browser and navigate to `http://localhost:5173`

## Usage

### Dashboard

The dashboard provides a quick overview of your vulnerability landscape, including:
- Current database status
- Total vulnerabilities tracked
- Indexed packages
- Last update timestamp

### Analytics

The Analytics page offers detailed insights into your vulnerability data:
- Severity distribution
- Trend analysis
- Package ecosystem statistics
- Time-based visualizations

### Visualizations

The Visualizations page provides interactive graph visualizations:
- Vulnerability-package relationships
- Dependency chains
- Impact analysis
- Custom filtering options

### Documentation

The Documentation page provides comprehensive information about:
- System architecture
- Data model
- API reference
- Usage examples

## Deployment

To build the application for production:

```bash
npm run build
```

The built files will be in the `dist` directory, ready to be deployed to your web server or cloud hosting platform.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with [Vue.js](https://vuejs.org/)
- Database powered by [Neo4j](https://neo4j.com/)
- Icons provided by [Font Awesome](https://fontawesome.com/)
