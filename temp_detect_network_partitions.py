"""
Temporary file containing the detect_network_partitions implementation
"""
from typing import List, Set

def detect_network_partitions(self) -> List[Set[str]]:
    """
    Detecta partições na rede P2P
    
    Returns:
        Lista de conjuntos de nós, onde cada conjunto representa uma partição
    """
    if not self.active_nodes:
        return []
        
    visited = set()
    partitions = []
    
    for node in self.active_nodes:
        if node not in visited:
            # Iniciar uma nova busca em largura para encontrar todos os nós conectados
            partition = set()
            queue = [node]
            
            while queue:
                current = queue.pop(0)
                if current not in visited:
                    visited.add(current)
                    partition.add(current)
                    
                    # Adicionar vizinhos não visitados à fila
                    if current in self.routing_table:
                        for neighbor in self.routing_table[current]:
                            if (neighbor in self.active_nodes and 
                                neighbor not in visited and 
                                self._can_reach_node(current, neighbor)):
                                queue.append(neighbor)
            
            if partition:
                partitions.append(partition)
    
    # Se não encontramos partições, retornar todos os nós como uma única partição
    if not partitions and self.active_nodes:
        return [set(self.active_nodes)]
        
    return partitions
