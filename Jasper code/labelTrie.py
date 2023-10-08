from model import Container, Policy

class TrieNode:
    def __init__(self, label = ''):
        self.label = label
        self.children = dict()
        self.is_label = False
        self.objects = []

class LabelTrie:
    def __init__(self):
        self.root = TrieNode()
  
    def insert(self, label, obj):
        current = self.root
        for i, char in enumerate(label):
            if char not in current.children:
                prefix = label[0:i+1]
                current.children[char] = TrieNode(prefix)
            current = current.children[char]
        current.is_label = True
        if isinstance(obj, Container):
            current.objects.append(obj)
        elif isinstance(obj, Policy):
            current.objects.append(obj)

    def find(self, label):
 
        current = self.root
        for char in label:
            if char not in current.children:
                return None
            current = current.children[char]

        if current.is_label:
            return current.objects
        else:
            return None     
           
    def __str__(self):
        def traverse(node, depth=0):
                
            result = "#" + "  " * depth + node.label + "\n#"
            if node.objects is not []:
                for obj in node.objects:
                    nodetext = "  " * (depth + 1) + obj.name
                    result += nodetext 
                result += "\n"
            for char, child in node.children.items():
                result += traverse(child, depth + 1)
            return result

        return traverse(self.root)
    
    def delete(self, label, obj):
        current = self.root
        nodes_to_delete = []

        for char in label:
            if char not in current.children:
                return
            nodes_to_delete.append(current)
            current = current.children[char]
        
        for objec in current.objects:
            if obj.id == objec.id:
                current.objects.remove(objec)
        if not current.objects:
            current.is_label = False
        # Check if the label node has no objects and no other labels as children
        while nodes_to_delete:
            node = nodes_to_delete.pop()
            if not node.is_label and not node.objects and not node.children:
                parent = nodes_to_delete[-1] if nodes_to_delete else self.root
                del parent.children[node.label[-1]]
    
if __name__ == "__main__":
    # Create an instance of the LabelTrie
    trie = LabelTrie()

    # Insert labels and objects into the trie
    container1 = Container(1, "Apple Container", {}, [], "Node1", [])
    container2 = Container(2, "Banana Container", {}, [], "Node2", [1])
    policy1 = Policy("Banana Policy 1", {}, [], False, [], None)
    policy2 = Policy("Banana Policy 2", {}, [], True, [], None)
    
    trie.insert("apple", container1)
    trie.insert("banana", container2)
    trie.insert("banana", policy1)
    trie.insert("banana", policy2)
    
    container3 = Container(3, "Cherry Container", {}, [], "Node3", [2])
    policy3 = Policy("Cherry Policy", {}, [], True, [], None)
    
    trie.insert("cherry", container3)
    trie.insert("cherry", policy3)

    # Print the state of the trie
    print("State of the Trie:")
    print(trie)

    # Test the find function
    label_to_find = "banana"
    objects_found = trie.find(label_to_find)
    if objects_found:
        print(f"Objects with label '{label_to_find}':")
        for obj in objects_found:
            print(obj)
    else:
        print(f"No objects found with label '{label_to_find}'")

    print(trie)