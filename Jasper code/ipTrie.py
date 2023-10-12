import ipaddress

def format_ip_range(ip_range):
        # Make an IP ranges like e.g. "a.b.c.d-e.f.g.h" into a range as "a:e.b:f.c:g.d.h"
        # If e.g. a = e it returns as "a.b:f.c:g.d.h"
        # IPs with subnetmask like a.b.c.d/e also get converted.

        # subnetmask check and conversion if so
        parts_slash = ip_range.split("/")
        if len(parts_slash) == 2:
            ip_range = ip_with_subnet_to_range(ip_range)
        
        # Split the input IP range into two parts: before '-' and after '-'
        parts = ip_range.split('-')

        if len(parts) == 1:
            return ip_range
    
        elif len(parts) != 2:
            raise ValueError("Invalid IP range format. Expected format: 'a.b.c.d-e.f.g.h' or 'a.b.c.d'")

        # Split each part into individual IP segments
        start_ip = parts[0].split('.')
        end_ip = parts[1].split('.')

        formatted_parts = []

        for start_segment, end_segment in zip(start_ip, end_ip):
            if start_segment == end_segment:
                formatted_parts.append(start_segment)
            else:
                formatted_parts.append(f"{start_segment}:{end_segment}")

        # Join the formatted segments with '.' to get the final formatted IP range
        final_string = '.'.join(formatted_parts)

        return final_string


def ip_with_subnet_to_range(ip_with_subnet):
    ip_str, subnet_str = ip_with_subnet.split('/')
    ip = ipaddress.ip_address(ip_str)
    network = ipaddress.ip_network(ip_with_subnet, strict=False)
    lowest_ip = network.network_address
    highest_ip = network.broadcast_address
    
    return f"{lowest_ip}-{highest_ip}"

class TrieNode:
    def __init__(self, nr = ''):
        self.nr = nr
        self.children = dict()
        self.is_ip = False
        # rules are stored as sets: (sgId, ruleId)
        self.ruleIds = []

class ProtocolNode:
    def __init__(self, protocol = ''):
        self.protocol = protocol
        self.children = dict()


class IpTrie:
    def __init__(self):
        # Create the top 3 nodes for the 3 kinds of protocols
        self.root = ProtocolNode()
        self.root.children["tcp"] = ProtocolNode("tcp")
        self.root.children["udp"] = ProtocolNode("udp")
        self.root.children["icmp"] = ProtocolNode("icmp")



    def insert(self, ip, protocol, ruleId, sgId):
        # IPs are given in as follows:
        #   - IP ranges: "a.b.c.d-a.b.e.f"
        #   - Single IP: "a.b.c.d"
        #   - IP with subnetmask: "a.b.c.d/e"
        current = self.root

        # First we sort per protocol. This way we dont need to go over all other protocol's ip ranges to find if it exists.
        if protocol not in current.children:
             raise ValueError("Error in finding the protocol. The supported protocols are tcp, udp or icmp")
        current = current.children[protocol]

        formatted_ip = format_ip_range(ip)
        formatted_ip_split = formatted_ip.split(".")

        for i, nr in enumerate(formatted_ip_split):            
            if nr not in current.children:
                prefix = ip[0:i+1]
                current.children[nr] = TrieNode(prefix)
            current = current.children[nr]
        current.is_ip = True
        current.ruleIds.append((sgId, ruleId))

    
    def findruleIdByIpAndProtocol(self, ip, protocol):
        # Returns the set (sgId, ruleId) representing the given ip as a rule if it exists and None otherwise.
        current = self.root

        if protocol not in current.children:
            raise ValueError("Error in finding the protocol. The supported protocols are tcp, udp or icmp")
        current = current.children[protocol]

        # If the given ip is a range or with subnet mask we need to look for each seperate ip.
        formatted_ip = format_ip_range(ip)
        formatted_ip_split = formatted_ip.split(".")    
        for ip_part in formatted_ip_split:
            found_match_for_ip_part = False
            if ":" in ip_part:
                # We have a range as ip parameter
                ip_part_split = ip_part.split(":")
                for child in current.children:
                        if ":" not in child:
                            # This child is not a range
                            # If the child is within the searched ip range we have a match
                            if (child >= ip_part_split[0] and child <= ip_part_split[1]):
                                current = current.children[child]
                                found_match_for_ip_part = True
                                break
                        else:
                            child_split = child.split(":")
                            # The child is also a range
                            # We have 2 ranges. We check whether the start or end of the searched ip part is within the start and end of the child part we are looking at.
                            if (int(ip_part_split[0]) >= int(child_split[0]) and int(ip_part_split[0]) <= int(child_split[1])) or (int(ip_part_split[1]) >= int(child_split[0]) and int(ip_part_split[1]) <= int(child_split[1])):
                                current = current.children[child]
                                found_match_for_ip_part = True
                                break
            else: 
                for child in current.children:
                    #  We have a single ip as parameter
                    if ":" not in child:
                        # This child is not a range so we compare directly
                        if child == ip_part:
                            current = current.children[child]
                            found_match_for_ip_part = True
                            break
                    else:
                        # The child is a range:
                        # We see if the searched ip part is within the range
                        child_split = child.split(":")
                        if (int(ip_part) >= int(child_split[0]) and int(ip_part) <= int(child_split[1])):
                            current = current.children[child]
                            found_match_for_ip_part = True
                            break

            if found_match_for_ip_part and current.is_ip :
                return current.ruleIds
        return None