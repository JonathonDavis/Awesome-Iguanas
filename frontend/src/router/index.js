import { createRouter, createWebHistory } from 'vue-router'
import Charts from '../views/Stats.vue'

const routes = [
  {
    path: '/',
    name: 'Home',
    component: () => import('../views/Home.vue')
  },
  {
    path: '/stats',
    name: 'Stats',
    component: Charts
  },
  {
    path: '/about',
    name: 'About',
    component: () => import('../views/About.vue')
  },
  // {
  //   path: '/graphs',
  //   name: 'Graphs',
  //   component: () => import('../views/Graphs.vue')
  // }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router