Access the Neo4j Browser:

Open a web browser and go to http://localhost:7474
Log in with your credentials (neo4j/jaguarai)


Run Basic Cypher Queries:
The Neo4j browser works with Cypher, a graph query language. Here are some useful queries to explore your vulnerability data:

View all vulnerabilities:
cypherCopyMATCH (v:Vulnerability) 
RETURN v 
LIMIT 25;

View vulnerabilities with affected packages:
cypherCopyMATCH (v:Vulnerability)-[:AFFECTS]->(p:Package) 
RETURN v, p 
LIMIT 25;

Find high severity vulnerabilities:
cypherCopyMATCH (v:Vulnerability) 
WHERE v.severity = "HIGH" 
RETURN v;

Explore references for a specific vulnerability (replace CVE-2021-44228 with any vulnerability ID you have):
cypherCopyMATCH (v:Vulnerability {id: "CVE-2021-44228"})-[:HAS_REFERENCE]->(r:Reference) 
RETURN v, r;

Count vulnerabilities by severity:
cypherCopyMATCH (v:Vulnerability)
RETURN v.severity, count(v) AS count
ORDER BY count DESC;

Find most vulnerable packages:
cypherCopyMATCH (v:Vulnerability)-[:AFFECTS]->(p:Package)
RETURN p.name, p.ecosystem, count(v) AS vulnerability_count
ORDER BY vulnerability_count DESC
LIMIT 10;



Visualize the Graph:

Neo4j Browser automatically visualizes your query results as a graph
Click on nodes to see their properties
Use the icons at the bottom of the visualization to adjust the display


Save Favorite Queries:

Click the star icon next to the query input box to save queries you use frequently


Explore the Schema:

Run :schema to see the database schema including node labels, relationship types, and indexes