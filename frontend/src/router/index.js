import { createRouter, createWebHistory } from 'vue-router'
import Charts from '../views/Charts.vue'

const routes = [
  {
    path: '/',
    name: 'Home',
    component: () => import('../views/Home.vue')
  },
  {
    path: '/charts',
    name: 'Charts',
    component: Charts
  },
  {
    path: '/about',
    name: 'About',
    component: () => import('../views/About.vue')
  },
  {
    path: '/upload',
    name: 'Upload',
    component: () => import('../views/Upload.vue')
  },
  {
    path: '/graphs',
    name: 'Graphs',
    component: () => import('../views/Graphs.vue')
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router