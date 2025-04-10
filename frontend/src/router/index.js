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
  routes
})

export default router