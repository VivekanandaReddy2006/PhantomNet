import sys
import os

sys.path.insert(0, os.path.abspath('backend'))
# pyrefly: ignore [missing-import]
from sentinel.rule_generator import deduplicate_rules

def main():
    snort_1 = 'alert tcp 192.168.1.5 any -> $HOME_NET 22 (msg:"SSH Brute Force"; sid:1001;)'
    snort_2 = 'alert tcp 192.168.1.5 any -> $HOME_NET 22 (msg:"SSH Brute Force"; sid:1002;)'
    snort_3 = 'alert tcp 192.168.1.5 any -> $HOME_NET 80 (msg:"SQLi Test"; sid:1003;)'
    
    sigma_1 = "title: 'Campaign CAMP-001 Detection'\nstatus: experimental\nlogsource:\n  category: network_traffic\ndetection:\n  selection:\n    src_ip: '10.0.0.1'\n  condition: selection\nlevel: high\n"
    sigma_2 = "title: 'Campaign CAMP-002 Detection'\nstatus: experimental\nlogsource:\n  category: network_traffic\ndetection:\n  selection:\n    src_ip: '10.0.0.1'\n  condition: selection\nlevel: high\n"
    sigma_3 = "title: 'Campaign CAMP-003 Detection'\nstatus: experimental\nlogsource:\n  category: network_traffic\ndetection:\n  selection:\n    src_ip: '192.168.1.200'\n  condition: selection\nlevel: high\n"
    
    rules = [snort_1, snort_2, snort_3, sigma_1, sigma_2, sigma_3]
    
    deduped = deduplicate_rules(rules)
    print(f"Original Rules: {len(rules)}")
    print(f"Deduped Rules: {len(deduped)}")
    
    for r in deduped:
        print("----")
        print(r)
        
    assert len(deduped) == 4, f"Expected 4, got {len(deduped)}"
    print("SUCCESS")

if __name__ == "__main__":
    main()
