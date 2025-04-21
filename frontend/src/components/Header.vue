<template>
  <header class="header">
    <nav class="nav-container">
      <div class="logo">
        <router-link to="/" class="logo-link" custom v-slot="{ navigate }">
          <div @click="navigate" class="logo-link">
            <img src="/dragon-svgrepo-com.svg" alt="Iguana's GPT" class="logo-img" />
            <span class="logo-text">Iguana's GPT</span>
          </div>
        </router-link>
      </div>      <div class="nav-links">
        <router-link to="/" class="nav-link" exact>
          <i class="fas fa-chart-pie"></i>
          <span>Dashboard</span>
        </router-link>
        <router-link to="/analytics" class="nav-link">
          <i class="fas fa-code-branch"></i>
          <span>Database Analytics</span>
        </router-link>
        <router-link to="/llm-evaluation" class="nav-link">
          <i class="fas fa-robot"></i>
          <span>LLM Evaluation</span>
        </router-link>
        <!-- <router-link to="/visualizations" class="nav-link">
          <i class="fas fa-shield-alt"></i>
          <span>Visualization</span>
        </router-link> -->
        <router-link to="/documentation" class="nav-link">
          <i class="fas fa-book"></i>
          <span>Documentation</span>
        </router-link>
      </div>
    </nav>
  </header>
</template>

<script setup>
// No setup needed for now
</script>

<style scoped>
.header {
  background-color: var(--primary-color);
  padding: 1rem;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
  position: sticky;
  top: 0;
  z-index: 100;
}

.nav-container {
  max-width: 1200px;
  margin: 0 auto;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.logo {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.logo-img {
  height: 2rem;
  width: 2rem;
  filter: brightness(0) invert(1);
}

.logo-text {
  color: white;
  font-size: 1.25rem;
  font-weight: 600;
  letter-spacing: 0.5px;
}

.nav-links {
  display: flex;
  gap: 0.5rem;
}

.nav-link {
  color: rgba(255, 255, 255, 0.85);
  text-decoration: none;
  padding: 0.5rem 1rem;
  border-radius: 4px;
  font-weight: 500;
  transition: all 0.2s ease;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.nav-link i {
  font-size: 0.9rem;
}

.nav-link:hover {
  background-color: rgba(255, 255, 255, 0.1);
  color: white;
}

.router-link-exact-active,
.router-link-active {
  background-color: var(--secondary-color);
  color: white;
}

.logo-link {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  text-decoration: none;
  color: inherit;
  cursor: pointer;
}

@media (max-width: 768px) {
  .nav-container {
    flex-direction: column;
    gap: 1rem;
  }
  
  .nav-links {
    width: 100%;
    justify-content: space-between;
    flex-wrap: wrap;
  }
  
  .nav-link {
    padding: 0.5rem;
    font-size: 0.9rem;
    flex-direction: column;
    text-align: center;
    gap: 0.25rem;
  }
  
  .nav-link i {
    font-size: 1rem;
  }
}
</style>