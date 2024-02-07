from model import Container, Policy

class TreeNode:
    def __init__(self, label = ''):
        self.label = label
        self.children = dict()
        self.is_label = False
        self.objects = []

class LabelTree:
    def __init__(self):
        self.root = TreeNode()
  
    def insert(self, label, obj):
        current = self.root
        split = label.split(":")
        for i in range(len(split)):
            part = split[i]
            if part not in current.children:
                current.children[part] = TreeNode(part)
            current = current.children[part]
            if i == len(split) - 1:  # If this is the last part of the label
                current.is_label = True
        if current.is_label:
            if isinstance(obj, Container) or isinstance(obj, Policy):
                current.objects.append(obj)

    def find(self, label):
    
        current = self.root
        for part in label.split(":"):
            if part not in current.children:
                return None
            current = current.children[part]

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

        for char in label.split(":"):
            if char not in current.children:
                return
            nodes_to_delete.append(current)
            current = current.children[char]
        
        for objec in current.objects:
            if obj.id == objec.id:
                current.objects.remove(objec)
        if not current.objects:
            current.is_label = False
        if not current.objects and not current.children:
        # Prune the node if no objects and children are left
            while nodes_to_delete:
                node = nodes_to_delete.pop()
                parent = nodes_to_delete[-1] if nodes_to_delete else self.root
                if node.label:
                    del parent.children[node.label]
