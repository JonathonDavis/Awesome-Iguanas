import { createRouter, createWebHistory } from 'vue-router'
import Analytics from '../views/Stats.vue'

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: () => import('../views/Home.vue')
  },
  {
    path: '/analytics',
    name: 'Analytics',
    component: Analytics
  },
  {
    path: '/documentation',
    name: 'Documentation',
    component: () => import('../views/About.vue')
  },
  {
    path: '/visualizations',
    name: 'Visualizations',
    component: () => import('../views/Graphs.vue')
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior(to, from, savedPosition) {
    if (to.hash) {
      return new Promise((resolve) => {
        // Add a small delay to ensure the component is rendered
        setTimeout(() => {
          resolve({
            el: to.hash,
            behavior: 'smooth',
            top: 80 // Increased offset to ensure the section is visible
          });
        }, 500); // 500ms delay should be sufficient
      });
    } else if (savedPosition) {
      return savedPosition;
    } else {
      return { top: 0 };
    }
  }
})

export default router