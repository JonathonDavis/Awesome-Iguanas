# Vue 3 + Vite

This template should help get you started developing with Vue 3 in Vite. The template uses Vue 3 `<script setup>` SFCs, check out the [script setup docs](https://v3.vuejs.org/api/sfc-script-setup.html#sfc-script-setup) to learn more.

Learn more about IDE Support for Vue in the [Vue Docs Scaling up Guide](https://vuejs.org/guide/scaling-up/tooling.html#ide-support).

# Frontend Documentation

This folder contains the frontend code for the Awesome Iguanas project. It is built using Vue 3 and Vite for a modern, fast, and modular development experience.

## Folder Structure

- **`index.html`**: The entry point for the application. It includes the root `div` where the Vue app is mounted.
- **`package.json`**: Contains the dependencies and scripts for managing the frontend project.
- **`vite.config.js`**: Configuration file for Vite, specifying plugins and build options.
- **`src/`**: The main source folder for the frontend application.
  - **`App.vue`**: The root Vue component that serves as the main layout for the app.
  - **`main.js`**: The entry JavaScript file that initializes the Vue app and sets up routing.
  - **`style.css`**: Contains the global styles for the application.
  - **`assets/`**: Contains .jpg images of the project contributors.
  - **`components/`**: Reusable Vue components.
    - **`Header.vue`**: The header component, including navigation links.
    - **`PieChart.vue`**: A component for rendering pie charts using Chart.js and Neo4j.
  - **`data/`**: Contains JSON files or other data used in the app.
    - **`teamMembers.json`**: Data about the team members displayed on the Home page.
  - **`router/`**: Contains the routing configuration for the app.
    - **`index.js`**: Defines the routes and their corresponding components.
  - **`services/`**: Contains service files for interacting with external APIs or databases.
    - **`neo4jService.js`**: Handles communication with the Neo4j database.
  - **`views/`**: Contains the main pages of the application.
    - **`Home.vue`**: The landing page of the application.
    - **`About.vue`**: Provides information about the project and contributors.
    - **`Stats.vue`**: Displays database statistics and visualizations.

## How to Run

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the development server:
   ```bash
   npm run dev
   ```

3. Open the application in your browser at `http://localhost:5173` (or the port specified by Vite).

## Key Features

- **Dynamic Routing**: The app uses Vue Router for navigation between pages.
- **Interactive Visualizations**: Includes charts and graphs for data analysis.
- **Database Integration**: Connects to Neo4j for graph-based data visualization.

## Dependencies

- **Vue 3**: The JavaScript framework used for building the user interface.
- **Vite**: A fast build tool and development server.
- **Vue Router**: For handling navigation between different views.
- **Chart.js**: For rendering interactive charts.
- **Neo4j Driver**: For connecting to the Neo4j database.

## Development

To contribute to this project:

1. Clone the repository
2. cd into /frontend using `cd frontend`
3. Install dependencies using `npm install`
4. Make your changes
5. Test your changes locally using `npm run dev`
6. Submit a pull request

## Build for Production

To build the application for production:

```bash
npm run build
```

The built files will be in the `dist` directory, ready to be deployed.
