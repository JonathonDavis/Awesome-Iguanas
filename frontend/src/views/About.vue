<template>
  <div class="about">
    <!-- ASCII Lizard -->
    <div class="ascii-lizard">
      <pre>

\ \ \ \ \ \ \ \ \| |\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \| |\ \ \ \ \ \ \ \ \ 
/ / / / / / / / / | | / / / / / / __  / / / / / / / / | | / / / / / / / / /
 \ \ \ \ \ \ \ \ \| |\ \ \ \ \   /..\  ` ` \ \ \ \ \ \| |\ \ \ \ \ \ \ \ \ 
------------------' `---------- (    ) \|/ -----------' `------------------
 ,------------------------- _\___>  <__//` ------------------------------. 
 |/ / / / / / / / / / / / / >,---.   ,-'  / / / / / / / / / / / / / / / /| 
 | \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ |  . \  \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ | 
 |/ / / / / / / / / / / / / / /  `. `. \   ., / / / / / / / / / / / / / /| 
 | \ \ \ \ \ \ \ \ \ \ \ \ \ \ \  |  `. | \||_ \ \ \ \ \ \ \ \ \ \ \ \ \ | 
 |/ / / / / / / / / / / / / / / / `.  : |__||   / / / / / / / / / / / / /| 
 | \ \ \ \ \ \ \ \ \ \ \ \ \ \ \  __> `.,---'  \ \ \ \ \ \ \ \ \ \ \ \ \ | 
 |/ / / / / / / / / / / / / / /  |.--'\`.\  / / / / / / / / / / / / / / /| 
 `------------------------------ _\\   \`.| -----------------------------' 
------------------. ,------------ /|\ - |:| ----------. ,------------------
 \ \ \ \ \ \ \ \ \| |\ \ \ \ \ \ ' `    |:|  \ \ \ \ \| |\ \ \ \ \ \ \ \ \ 
/ / / / / / / / / | | / / / / / / / / / |:| / / / / / | | / / / / / / / / /
 \ \ \ \ \ \ \ \ \| |\ \ \ \ \ \ \ \ \  |:/  \ \ \ \ \| |\ \ \ \ \ \ \ \ \ 
/ / / / / / / / / | | / /  --.________,-_/  / / / / / | | / / / / / / / / /
 \ \ \ \ \ \ \ \ \| |\ \ \ \ \ ```-----' \ \ \ \ \ \ \| |\ \ \ \ \ \ \ \ \ 
/ / / / / / / / / | | / / / / / / / / / / / / / / / / | | / / / / / / / / / 
      </pre>
    </div>
    <h1>About Iguana's GPT</h1>
    <p>
      Iguana's GPT is a cutting-edge vulnerability detection tool designed to help developers identify and resolve software vulnerabilities efficiently. 
      This project leverages Neo4j for graph-based data storage and visualization, along with Vue.js for an intuitive user interface.
    </p>
    <h2>Features</h2>
    <ul>
      <li>Dynamic solutions for memory safety vulnerabilities in any programming language.</li>
      <li>Constantly updating CWE database logic.</li>
      <li>User-friendly online interface for developers of all skill levels.</li>
    </ul>
    <h2>Contributors</h2>
    <ul>
      <li>Matthew Trevino - Team Lead & Backend Developer</li>
      <li>Jonathon Davis - Frontend Developer</li>
      <li>Joshua Ludolf - Backend Developer</li>
      <li>Samantha Jackson - Frontend Developer</li>
      <li>Alexandar James - Backend Developer</li>
      <li>Yesmin Hernandez - Frontend Developer</li>
    </ul>
    <h2>Learn More</h2>
    <p>
      For more information, visit our <a href="https://github.com/JonathonDavis/Awesome-Iguanas" target="_blank">GitHub repository</a>.
    </p>
  </div>
</template>

<style scoped>
.about {
  margin: 2rem;
  padding: 2rem;
  border: 1px solid #ffffff;
  border-radius: 8px;
  line-height: 1.6;
  background-color: #259a67;
  color: #A2E656;
  text-align: center;
}

.ascii-lizard {
  font-family: monospace;
  color: white;
  margin-bottom: 2rem;
 background: rgba(44, 44, 44, 0.8);
  padding: 1rem;
  border-radius: 4px;
  overflow-x: auto;
}

h1 {
  color: white;
  margin-bottom: 1.5rem;
  font-size: 2rem;
}

h2 {
  color: white;
  margin: 2rem 0 1rem;
  font-size: 1.5rem;
}

p {
  color: white;
  margin-bottom: 1rem;
  font-size: 1.1rem;
}

ul {
  list-style: none;
  padding: 0;
  margin: 1rem 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
}

li {
  display: flex;
  align-items: center;
  margin-bottom: 0.5rem;
  background: rgba(44, 44, 44, 0.8);
  padding: 0.5rem 1rem;
  border-radius: 4px;
  width: 100%;
  max-width: 600px;
  border: 1px solid rgba(255, 255, 255, 0.1);
}

li::before {
  content: "•";
  color: #259a67;
  font-size: 1.5rem;
  margin-right: 0.5rem;
}

a {
  color: white;
  text-decoration: none;
  background: rgba(255, 255, 255, 0.1);
  padding: 0.5rem 1rem;
  border-radius: 4px;
  transition: background-color 0.3s;
}

a:hover {
  background: rgba(255, 255, 255, 0.2);
  text-decoration: none;
}

@media (max-width: 768px) {
  .about {
    margin: 1rem;
    padding: 1rem;
  }

  .ascii-lizard {
    font-size: 0.8rem;
  }

  h1 {
    font-size: 1.5rem;
  }

  h2 {
    font-size: 1.2rem;
  }
}
</style>