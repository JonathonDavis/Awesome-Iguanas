// This is a temporary file for the fix that will be applied to Graphs.vue
// Function to check if source and target nodes exist in the nodes array
function validateLinks(nodes, relationships) {
  // Create a set of node IDs for quick lookup
  const nodeIdSet = new Set(nodes.map(node => node.id.toString()));
  
  // Filter relationships to only include those with both source and target nodes in the dataset
  return relationships.filter(link => {
    const sourceExists = nodeIdSet.has(link.source.toString());
    const targetExists = nodeIdSet.has(link.target.toString());
    
    if (!sourceExists || !targetExists) {
      console.debug(`Skipping invalid relationship: ${link.id} (${link.source} -> ${link.target})`);
      return false;
    }
    return true;
  });
}
