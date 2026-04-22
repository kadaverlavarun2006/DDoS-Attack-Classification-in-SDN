import time
from collections import defaultdict

class TrafficAnalyzer:
    def __init__(self, request_threshold=20, ddos_threshold=100, ip_threshold=10, time_window=5):
        self.request_threshold = request_threshold
        self.ddos_threshold = ddos_threshold
        self.ip_threshold = ip_threshold
        self.time_window = time_window
        self.traffic_data = defaultdict(list)

    def add_request(self, ip):
        current_time = time.time()
        self.traffic_data[ip].append(current_time)

        # Remove old requests outside time window
        self.traffic_data[ip] = [
            t for t in self.traffic_data[ip]
            if current_time - t <= self.time_window
        ]

    def detect_dos(self, ip):
        if len(self.traffic_data[ip]) > self.request_threshold:
            return True
        return False

    def detect_ddos(self):
        total_requests = sum(len(v) for v in self.traffic_data.values())
        unique_ips = len(self.traffic_data)

        if total_requests > self.ddos_threshold and unique_ips > self.ip_threshold:
            return True
        return False

    def analyze(self, ip):
        self.add_request(ip)

        if self.detect_dos(ip):
            return f"⚠️ DoS Attack detected from {ip}"

        if self.detect_ddos():
            return "🚨 DDoS Attack detected in network"

        return f"✅ Normal traffic from {ip}"
    
analyzer = TrafficAnalyzer()


#print("\nTest Case 1: Normal Traffic")
#for i in range(5):
#    print(analyzer.analyze("192.168.1.1"))
#    time.sleep(1) 


#analyzer = TrafficAnalyzer()
'''
print("\nTest Case 2: DoS Attack")
for i in range(25):
    print(analyzer.analyze("192.168.1.100"))
    time.sleep(0.1)
'''


'''
analyzer = TrafficAnalyzer()

print("\nTest Case 4: Burst Traffic (Short spike)")

for i in range(15):
    print(analyzer.analyze("192.168.1.50"))

time.sleep(6)  # wait beyond window

for i in range(5):
    print(analyzer.analyze("192.168.1.50"))
'''

'''

analyzer = TrafficAnalyzer()

print("\nTest Case 3: DDoS Attack")

for i in range(25):
    ip = f"192.168.1.{i}"
    for _ in range(3):
        print(analyzer.analyze(ip))
'''

'''
analyzer = TrafficAnalyzer()

print("\nTest Case 4: Mixed Traffic")

# Normal users
for i in range(5):
    print(analyzer.analyze(f"192.168.1.{i}"))

# Attacker
for i in range(25):
    print(analyzer.analyze("192.168.1.250"))    
'''