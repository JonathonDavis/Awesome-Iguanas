<template>
  <div class="home">
    <h1>Welcome to Iguana's GPT</h1>
    <div class="description">
      <p>This project is made in collaboration of 6 determined Texas A&M University-San Antonio students for our class, Senior Project.</p>
      
      <div class="team-section">
        <h2>Our Team</h2>
        <div class="team-grid">
          <div v-for="member in teamData.teamMembers" 
               :key="member.id" 
               class="team-member">
            <div class="member-photo">
              <img :src="member.imageUrl" 
                   :alt="member.name" />
            </div>
            <h3>{{ member.name }}</h3>
            <p class="member-role">{{ member.role }}</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import teamData from '../data/teamMembers.json';
</script>

<style scoped>
.home {
  text-align: center;
  padding: 2rem;
  max-width: 1200px;
  margin: 0 auto;
}

.description {
  margin-top: 2rem;
  line-height: 1.6;
}

h1 {
  color: #259a67;
  margin-bottom: 1.5rem;
}

h2 {
  color: #259a67;
  margin: 2rem 0 1rem;
}

h3 {
  color: #d56a6a;
  margin: 0.5rem 0;
}

p {
  margin-bottom: 1rem;
  font-size: 1.1rem;
  font-family: sans-serif;
}

.team-section {
  margin: 2rem 0;
  padding: 2rem;
  background-color: rgba(37, 154, 103, 0.1);
  border-radius: 8px;
}

.team-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 2rem;
  padding: 1rem;
}

.team-member {
  background: rgba(15, 137, 118, 0.271);
  padding: 1rem;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  transition: transform 0.2s;
}

.team-member:hover {
  transform: translateY(-5px);
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
}

.member-photo {
  width: 150px;
  height: 150px;
  margin: 0 auto;
  border-radius: 50%;
  overflow: hidden;
  border: 3px solid #259a67;
}

.member-photo img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.member-role {
  color: #efeeeef5;
  font-size: 0.9rem;
  margin: 0.5rem 0;
}
</style>