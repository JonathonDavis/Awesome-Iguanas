<script setup>
import Header from './components/Header.vue'
</script>

<template>
  <div class="app">
    <Header />
    <main class="main-content">
      <router-view></router-view>
    </main>
  </div>
</template>

<style>
body {
  margin: 0;
  padding: 0;
  font-family: Arial, sans-serif;
}

.app {
  min-height: 100vh;
  min-width: 100%;
  width: 100%;
  max-width: 1000px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
}

.main-content {
  flex: 1;
  padding: 1rem;
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
</style>