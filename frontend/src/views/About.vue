<template>
  <div class="documentation">
    <div class="doc-header">
      <h1>About Iguana's GPT</h1>
      <p class="subtitle">Database Vulnerability Management System</p>
    </div>
    
    <div class="doc-container">
      <aside class="doc-sidebar">
        <nav class="sidebar-nav">
          <ul>
            <li v-for="section in sections" :key="section.id">
              <a :href="`#${section.id}`" :class="{ active: activeSection === section.id }">{{ section.title }}</a>
            </li>
          </ul>
        </nav>
      </aside>
      
      <main class="doc-content">
        <section id="overview" class="doc-section">
          <h2>Overview</h2>
          <p>
            Iguana's GPT is an enterprise-grade database vulnerability management solution designed to help organizations identify, assess, and remediate security vulnerabilities in their database systems. The system uses Neo4j graph database to store and analyze complex vulnerability relationships.
          </p>
          <div class="feature-grid">
            <div class="feature-card">
              <div class="feature-icon"><i class="fas fa-shield-alt"></i></div>
              <h3>Vulnerability Tracking</h3>
              <p>Complete vulnerability lifecycle management with severity classification and affected package tracking.</p>
            </div>
            <div class="feature-card">
              <div class="feature-icon"><i class="fas fa-project-diagram"></i></div>
              <h3>Relationship Analysis</h3>
              <p>Graph-based visualization of dependencies and impact paths across your software ecosystem.</p>
            </div>
            <div class="feature-card">
              <div class="feature-icon"><i class="fas fa-chart-line"></i></div>
              <h3>Analytics Dashboard</h3>
              <p>Comprehensive analytics to understand vulnerability trends and security posture.</p>
            </div>
          </div>
        </section>
        
        <section id="architecture" class="doc-section">
          <h2>System Architecture</h2>
          <p>
            Iguana's GPT follows a modern microservices architecture with the following components:
          </p>
          <ul class="architecture-list">
            <li><strong>Frontend:</strong> Vue.js based responsive UI for data visualization and management</li>
            <li><strong>API Layer:</strong> RESTful service endpoints for data access and manipulation</li>
            <li><strong>Database:</strong> Neo4j graph database for storing vulnerability and package relationships</li>
            <li><strong>Data Processor:</strong> Background services for vulnerability data ingestion and analysis</li>
          </ul>
          <div class="code-block">
            <pre><code>// Example Neo4j Connection
import neo4j from 'neo4j-driver'

const driver = neo4j.driver(
  'neo4j://localhost:7687',
  neo4j.auth.basic('username', 'password')
)

const session = driver.session()</code></pre>
          </div>
        </section>
        
        <section id="data-model" class="doc-section">
          <h2>Data Model</h2>
          <p>
            The core data model consists of the following primary entities:
          </p>
          <ul class="model-list">
            <li><strong>Vulnerability:</strong> Central entity containing vulnerability details, severity, and references</li>
            <li><strong>Package:</strong> Software packages that may contain vulnerabilities</li>
            <li><strong>AFFECTS:</strong> Relationship between vulnerabilities and packages, including version ranges</li>
          </ul>
          <div class="diagram">
            <p class="diagram-caption">Simplified Entity Relationship Diagram</p>
            <div class="diagram-content">
              <div class="entity">Vulnerability</div>
              <div class="relationship">AFFECTS →</div>
              <div class="entity">Package</div>
            </div>
          </div>
        </section>
        
        <section id="api" class="doc-section">
          <h2>API Reference</h2>
          <p>
            Iguana's GPT exposes a comprehensive REST API for integrating with your existing systems.
          </p>
          <div class="api-endpoints">
            <div class="endpoint">
              <div class="method get">GET</div>
              <div class="path">/api/v1/vulnerabilities</div>
              <div class="description">Retrieve all vulnerabilities with pagination support</div>
            </div>
            <div class="endpoint">
              <div class="method get">GET</div>
              <div class="path">/api/v1/vulnerabilities/:id</div>
              <div class="description">Get detailed information about a specific vulnerability</div>
            </div>
            <div class="endpoint">
              <div class="method post">POST</div>
              <div class="path">/api/v1/vulnerabilities</div>
              <div class="description">Create a new vulnerability record</div>
            </div>
            <div class="endpoint">
              <div class="method get">GET</div>
              <div class="path">/api/v1/packages/:ecosystem/:name</div>
              <div class="description">Retrieve package information with vulnerabilities</div>
            </div>
          </div>
        </section>
        
        <section id="usage" class="doc-section">
          <h2>Usage Examples</h2>
          <p>
            Get started quickly with these common usage examples:
          </p>
          <div class="usage-example">
            <h3>Search for vulnerabilities affecting a specific package</h3>
            <div class="code-block">
              <pre><code>// Example API request
const response = await fetch('/api/v1/vulnerabilities?package=lodash&ecosystem=npm');
const vulnerabilities = await response.json();

console.log(`Found ${vulnerabilities.length} vulnerabilities affecting lodash`);</code></pre>
            </div>
          </div>
          <div class="usage-example">
            <h3>Generate a vulnerability report</h3>
            <p>
              Navigate to the Analytics dashboard to generate comprehensive reports on your vulnerability landscape.
            </p>
          </div>
        </section>
        
        <section id="team" class="doc-section">
          <h2>Meet the Team</h2>
          <p>
            Our talented team of developers working on Iguana's GPT:
          </p>
          
          <div class="team-grid">
            <div v-for="member in teamMembers" :key="member.id" class="team-card">
              <div class="member-image">
                <img :src="member.imageUrl" :alt="member.name">
              </div>
              <h3>{{ member.name }}</h3>
              <p class="member-role">{{ member.role }}</p>
            </div>
          </div>
        </section>
      </main>
    </div>
  </div>
</template>

<script>
import teamMembersData from '../data/teamMembers.json';

export default {
  data() {
    return {
      teamMembers: teamMembersData.teamMembers,
      sections: [
        { id: 'overview', title: 'Overview' },
        { id: 'architecture', title: 'System Architecture' },
        { id: 'data-model', title: 'Data Model' },
        { id: 'api', title: 'API Reference' },
        { id: 'usage', title: 'Usage Examples' },
        { id: 'team', title: 'Meet the Team' }
      ],
      activeSection: 'overview'
    };
  },
  mounted() {
    window.addEventListener('scroll', this.handleScroll);
    this.handleScroll(); // Set initial active section
  },
  beforeUnmount() {
    window.removeEventListener('scroll', this.handleScroll);
  },
  methods: {
    handleScroll() {
      // Get all section elements
      const sectionElements = this.sections.map(section => ({
        id: section.id,
        element: document.getElementById(section.id)
      })).filter(item => item.element);
      
      // Calculate which section is most visible in the viewport
      let mostVisibleSection = null;
      let maxVisibility = 0;
      
      sectionElements.forEach(({ id, element }) => {
        const rect = element.getBoundingClientRect();
        const windowHeight = window.innerHeight;
        
        // Calculate how much of the section is visible
        const visibleTop = Math.max(0, rect.top);
        const visibleBottom = Math.min(windowHeight, rect.bottom);
        const visibleHeight = Math.max(0, visibleBottom - visibleTop);
        
        // Weight visibility towards the top of the viewport for better UX
        const topProximity = 1 - (Math.max(0, visibleTop) / windowHeight);
        const visibilityScore = visibleHeight * (1 + topProximity);
        
        if (visibilityScore > maxVisibility) {
          maxVisibility = visibilityScore;
          mostVisibleSection = id;
        }
      });
      
      if (mostVisibleSection) {
        this.activeSection = mostVisibleSection;
      }
    }
  }
};
</script>

<style scoped>
.documentation {
  color: var(--text-color);
  background-color: var(--background-color);
}

.doc-header {
  text-align: center;
  margin-bottom: 2rem;
  padding-bottom: 2rem;
  border-bottom: 1px solid var(--border-color);
}

.doc-header h1 {
  color: var(--primary-color);
  font-size: 2rem;
  margin-bottom: 0.5rem;
}

.subtitle {
  color: var(--light-text);
  font-size: 1.1rem;
}

.doc-container {
  display: grid;
  grid-template-columns: 250px 1fr;
  gap: 2rem;
}

.doc-sidebar {
  position: sticky;
  top: 2rem;
  height: calc(100vh - 200px);
  overflow-y: auto;
}

.sidebar-nav ul {
  list-style: none;
  padding: 0;
  margin: 0;
}

.sidebar-nav li {
  margin-bottom: 0.5rem;
}

.sidebar-nav a {
  display: block;
  padding: 0.75rem 1rem;
  color: var(--text-color);
  text-decoration: none;
  border-radius: 4px;
  transition: all 0.2s ease;
}

.sidebar-nav a:hover {
  background-color: rgba(0, 0, 0, 0.05);
}

.sidebar-nav a.active {
  background-color: var(--accent-color);
  color: white;
}

.doc-content {
  padding-bottom: 4rem;
}

.doc-section {
  margin-bottom: 3rem;
  padding-bottom: 2rem;
  border-bottom: 1px solid var(--border-color);
}

.doc-section:last-child {
  border-bottom: none;
}

.doc-section h2 {
  color: var(--primary-color);
  font-size: 1.6rem;
  margin-bottom: 1rem;
  padding-bottom: 0.5rem;
  border-bottom: 2px solid var(--accent-color);
  display: inline-block;
}

.doc-section h3 {
  color: var(--secondary-color);
  font-size: 1.2rem;
  margin: 1.5rem 0 0.75rem;
}

.doc-section p {
  margin-bottom: 1rem;
  line-height: 1.6;
}

.feature-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1.5rem;
  margin-top: 2rem;
}

.feature-card {
  background-color: white;
  border-radius: 8px;
  padding: 1.5rem;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.feature-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1);
}

.feature-icon {
  background-color: rgba(66, 153, 225, 0.1);
  color: var(--accent-color);
  width: 50px;
  height: 50px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.5rem;
  margin-bottom: 1rem;
}

.architecture-list, .model-list {
  margin: 1rem 0 2rem;
  padding-left: 1.5rem;
  line-height: 1.8;
}

.architecture-list li, .model-list li {
  margin-bottom: 0.75rem;
}

.code-block {
  background-color: #1a2942;
  border-radius: 6px;
  padding: 1.5rem;
  margin: 1.5rem 0;
  overflow-x: auto;
}

.code-block pre {
  margin: 0;
}

.code-block code {
  color: #e2e8f0;
  font-family: 'Fira Code', monospace;
  font-size: 0.9rem;
  line-height: 1.6;
}

.diagram {
  margin: 2rem 0;
  text-align: center;
}

.diagram-caption {
  font-weight: 600;
  margin-bottom: 1rem;
  color: var(--secondary-color);
}

.diagram-content {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 1rem;
}

.entity {
  background-color: var(--accent-color);
  color: white;
  padding: 0.75rem 1.5rem;
  border-radius: 4px;
  font-weight: 600;
}

.relationship {
  color: var(--light-text);
  font-weight: 600;
}

.api-endpoints {
  margin: 1.5rem 0;
}

.endpoint {
  display: grid;
  grid-template-columns: 80px 1fr 1fr;
  align-items: center;
  margin-bottom: 0.75rem;
  padding: 0.75rem;
  background-color: white;
  border-radius: 4px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
}

.method {
  font-weight: 600;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  text-align: center;
  font-size: 0.9rem;
}

.method.get {
  background-color: #48bb78;
  color: white;
}

.method.post {
  background-color: #4299e1;
  color: white;
}

.path {
  font-family: 'Fira Code', monospace;
  color: var(--primary-color);
  font-weight: 500;
}

.usage-example {
  margin: 2rem 0;
}

.team-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 1.5rem;
  margin-top: 2rem;
}

.team-card {
  background-color: white;
  border-radius: 8px;
  padding: 1.5rem;
  box-shadow: 0 3px 8px rgba(0, 0, 0, 0.08);
  text-align: center;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.team-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 8px 16px rgba(0, 0, 0, 0.12);
}

.member-image {
  width: 120px;
  height: 120px;
  margin: 0 auto 1rem;
  border-radius: 50%;
  overflow: hidden;
  border: 3px solid var(--accent-color);
}

.member-image img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.team-card h3 {
  margin-bottom: 0.3rem;
}

.member-role {
  color: var(--secondary-color);
  font-size: 0.9rem;
}

@media (max-width: 768px) {
  .doc-container {
    grid-template-columns: 1fr;
  }
  
  .doc-sidebar {
    position: static;
    height: auto;
    margin-bottom: 2rem;
  }
  
  .endpoint {
    grid-template-columns: 70px 1fr;
    grid-template-rows: auto auto;
  }
  
  .path {
    grid-column: 2;
  }
  
  .description {
    grid-column: 1 / -1;
    margin-top: 0.5rem;
  }
}
</style>