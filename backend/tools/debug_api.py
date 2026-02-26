import requests
import json

BASE_URL = "http://localhost:8000"

def debug_api():
    # 1. Login
    try:
        resp = requests.post(f"{BASE_URL}/api/auth/login", json={"username": "admin", "password": "admin"})
        if resp.status_code != 200:
            print(f"Login Failed: {resp.text}")
            return
        
        token = resp.json().get("access_token")
        headers = {"Authorization": f"Bearer {token}"}
        
        # 2. Fetch Topology
        print("\n--- Topology Data ---")
        topo_resp = requests.get(f"{BASE_URL}/api/network/topology", headers=headers)
        if topo_resp.status_code == 200:
            data = topo_resp.json()
            nodes = data.get('nodes', [])
            print(f"Node Count: {len(nodes)}")
            if nodes:
                print("Sample Node 0:", json.dumps(nodes[0], indent=2))
        else:
            print(f"Topology Failed: {topo_resp.text}")

        # 3. Fetch Geo Stats
        print("\n--- Geo Data ---")
        geo_resp = requests.get(f"{BASE_URL}/api/stats/geo", headers=headers)
        if geo_resp.status_code == 200:
            geo_data = geo_resp.json()
            print("Geo Data:", json.dumps(geo_data[:5], indent=2) if geo_data else "Empty")
        else:
            print(f"Geo Failed: {geo_resp.text}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    debug_api()
