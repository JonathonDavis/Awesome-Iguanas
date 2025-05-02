<template>
  <div class="llm-evaluation-view">
    <div class="header-section">
      <h1>LLM Vulnerability Evaluation</h1>
      <div class="header-graphic">
        <i class="fas fa-shield-alt shield-icon"></i>
        <i class="fas fa-brain brain-icon"></i>
        <i class="fas fa-code code-icon"></i>
      </div>
    </div>
    
    <div class="info-panel">
      <div class="info-icon">
        <i class="fas fa-info-circle"></i>
      </div>
      <div class="info-content">
        <h3>About This Tool</h3>
        <p class="description" data-v-8c6c0e87="">
          This advanced tool leverages Large Language Model ({{ ollamaModel }}) technology to perform deep analysis of repository code revisions for potential security vulnerabilities. The system provides comprehensive reports highlighting areas of concern, affected files and functions, and classification of vulnerability severity.
        </p>
      </div>
    </div>
    
    <div class="features-grid">
      <div class="feature-card">
        <i class="fas fa-search"></i>
        <h3>Deep Code Analysis</h3>
        <p>Scan repositories for security issues using AI-powered code review</p>
      </div>
      <div class="feature-card">
        <i class="fas fa-chart-pie"></i>
        <h3>Vulnerability Metrics</h3>
        <p>Get detailed statistics and classification of detected vulnerabilities</p>
      </div>
      <div class="feature-card">
        <i class="fas fa-code-branch"></i>
        <h3>Repository Integration</h3>
        <p>Analyze existing repositories or upload custom code for evaluation</p>
      </div>
    </div>
    
    <div class="evaluation-component">
      <LLMVulnerabilityEvaluation />
    </div>
  </div>
</template>

<script>
import LLMVulnerabilityEvaluation from '../components/LLMVulnerabilityEvaluation.vue';

export default {
  name: 'LLMEvaluation',
  components: {
    LLMVulnerabilityEvaluation
  },
  data() {
    return {
      ollamaModel: import.meta.env.VITE_OLLAMA_MODEL || 'deepseek-r1:7b'
    };
  }
}
</script>

<style scoped>
.llm-evaluation-view {
  max-width: 1200px;
  margin: 0 auto;
  padding: 1rem;
}

.header-section {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
  padding-bottom: 1.5rem;
  border-bottom: 2px solid var(--accent-color, #3498db);
}

.header-graphic {
  display: flex;
  align-items: center;
  font-size: 2.5rem;
  color: var(--accent-color, #3498db);
}

.shield-icon, .brain-icon, .code-icon {
  margin: 0 0.5rem;
  animation: pulse 2s infinite alternate;
}

.brain-icon {
  animation-delay: 0.5s;
}

.code-icon {
  animation-delay: 1s;
}

@keyframes pulse {
  from { opacity: 0.7; transform: scale(1); }
  to { opacity: 1; transform: scale(1.1); }
}

h1 {
  font-size: 2.5rem;
  color: var(--primary-color, #2c3e50);
  margin: 0;
}

.info-panel {
  display: flex;
  background: linear-gradient(135deg, rgba(52, 152, 219, 0.1), rgba(52, 152, 219, 0.2));
  border-radius: 10px;
  padding: 1.5rem;
  margin-bottom: 2rem;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
  border-left: 4px solid var(--accent-color, #3498db);
}

.info-icon {
  font-size: 2rem;
  color: var(--accent-color, #3498db);
  margin-right: 1.5rem;
  display: flex;
  align-items: center;
}

.info-content h3 {
  margin-top: 0;
  color: var(--accent-color, #3498db);
}

.description {
  margin-bottom: 0;
  color: var(--text-color, #333);  line-height: 1.6;
  font-size: 1.05rem;
}

.features-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2.5rem;
}

.feature-card {
  background-color: white;
  border-radius: 10px;
  padding: 1.5rem;
  box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05);
  transition: all 0.3s ease;
  text-align: center;
  border-top: 4px solid var(--accent-color, #3498db);
}

.feature-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
}

.feature-card i {
  font-size: 2.5rem;
  margin-bottom: 1rem;
  color: var(--accent-color, #3498db);
}

.feature-card h3 {
  font-size: 1.2rem;
  margin-bottom: 0.75rem;
  color: var(--primary-color, #2c3e50);
}

.feature-card p {
  color: var(--light-text, #666);
  line-height: 1.5;
  margin: 0;
}

.evaluation-component {
  background-color: white;
  border-radius: 12px;
  box-shadow: 0 6px 18px rgba(0, 0, 0, 0.08);
  padding: 1.5rem;
  margin-top: 1rem;
}

@media (max-width: 768px) {
  .header-section {
    flex-direction: column;
    text-align: center;
  }
  
  .header-graphic {
    margin-top: 1rem;
  }
  
  .info-panel {
    flex-direction: column;
  }
  
  .info-icon {
    margin-right: 0;
    margin-bottom: 1rem;
    justify-content: center;
  }
  
  .features-grid {
    grid-template-columns: 1fr;
  }
}
</style>
