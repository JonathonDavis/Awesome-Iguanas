<script setup>
import Header from './components/Header.vue'
</script>

<template>
  <div class="app">
    <Header />
    <main class="main-content">
      <router-view></router-view>
    </main>
    <footer class="footer">
      <div class="footer-content">
        <p>&copy; 2025 DataVault Pro. All rights reserved.</p>
      </div>
    </footer>
  </div>
</template>

<style>
:root {
  --primary-color: #1a2942;
  --secondary-color: #2c5282;
  --accent-color: #4299e1;
  --text-color: #2d3748;
  --light-text: #718096;
  --background-color: #f7fafc;
  --card-background: #ffffff;
  --border-color: #e2e8f0;
  --error-color: #e53e3e;
  --success-color: #48bb78;
  --warning-color: #ed8936;
}

body {
  margin: 0;
  padding: 0;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
  background-color: var(--background-color);
  color: var(--text-color);
  line-height: 1.5;
}

.app {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

.main-content {
  flex: 1;
  width: 100%;
  max-width: 1200px;
  margin: 0 auto;
  padding: 2rem 1rem;
}

.footer {
  background-color: var(--primary-color);
  color: white;
  padding: 1rem;
  text-align: center;
}

.footer-content {
  max-width: 1200px;
  margin: 0 auto;
}

@media (min-width: 768px) {
  .main-content {
    padding: 2rem;
  }
}

@media (max-width: 767px) {
  .main-content {
    padding: 1rem;
  }
}

/* Global utility classes */
.card {
  background-color: var(--card-background);
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
  padding: 1.5rem;
  margin-bottom: 1.5rem;
}

.heading-primary {
  color: var(--primary-color);
  font-size: 1.8rem;
  margin-bottom: 1.5rem;
}

.heading-secondary {
  color: var(--secondary-color);
  font-size: 1.4rem;
  margin-bottom: 1rem;
}

.text-accent {
  color: var(--accent-color);
}

.text-success {
  color: var(--success-color);
}

.text-error {
  color: var(--error-color);
}

.text-warning {
  color: var(--warning-color);
}

button {
  cursor: pointer;
  border: none;
  border-radius: 4px;
  padding: 0.5rem 1rem;
  font-weight: 500;
  transition: all 0.2s ease;
}

button.primary {
  background-color: var(--accent-color);
  color: white;
}

button.primary:hover {
  background-color: var(--secondary-color);
}

button.secondary {
  background-color: white;
  border: 1px solid var(--border-color);
  color: var(--text-color);
}

button.secondary:hover {
  background-color: var(--background-color);
}
</style>