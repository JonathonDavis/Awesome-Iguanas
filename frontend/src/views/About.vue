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
  padding: 2rem;
  line-height: 1.6;
  background-color: #2c2c2c; /* Dark grey background */
  color: #f5f5f5; /* Light text color for contrast */
  border-radius: 8px; /* Optional: Add rounded corners for better aesthetics */
  text-align: center; /* Center-align content */
}

.ascii-lizard {
  font-family: monospace; /* Use monospace font for ASCII art */
  color: #4caf50; /* Bright green color for the lizard */
  margin-bottom: 1rem; /* Add spacing below the ASCII art */
}

h1, h2 {
  color: #4caf50; /* Bright green for headings */
}

p, ul {
  color: #f5f5f5; /* Light text color for paragraphs and lists */
}

ul {
  list-style: none; /* Remove default bullet points */
  padding: 0;
  margin-left: 0;
}

li {
  display: flex;
  align-items: center;
  margin-bottom: 0.5rem;
}

li::before {
  content: "•"; /* Custom bullet point */
  color: #4caf50; /* Bright green for the bullet */
  font-size: 1.5rem;
  margin-right: 0.5rem;
}

li:hover {
  color: #82b1ff; /* Light blue text on hover */
  transition: color 0.3s ease;
}

a {
  color: #82b1ff; /* Light blue for links */
  text-decoration: none;
}

a:hover {
  text-decoration: underline;
}
</style>