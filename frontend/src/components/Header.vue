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
      </div>
      <div class="nav-links">
        <router-link to="/" class="nav-link">Home</router-link>
        <router-link to="/charts" class="nav-link">Charts</router-link>
        <router-link to="/graphs" class="nav-link">Graphs</router-link>
        <router-link to="/about" class="nav-link">About</router-link>
      </div>
    </nav>
  </header>
</template>

<script setup>
// No setup needed for now
</script>

<style scoped>
.header {
  background-color: #259a67;
  padding: 1rem;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
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
}

.logo-text {
  color: white;
  font-size: 1.25rem;
  font-weight: bold;
}

.nav-links {
  display: flex;
  gap: 1rem;
}

.nav-link {
  color: white;
  text-decoration: none;
  padding: 0.5rem 1rem;
  border-radius: 4px;
  transition: background-color 0.3s;
}

.nav-link:hover {
  background-color: rgba(255, 255, 255, 0.1);
}

.router-link-active {
  background-color: rgba(255, 255, 255, 0.2);
}

.logo-link {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  text-decoration: none;
  color: inherit;
}

</style>