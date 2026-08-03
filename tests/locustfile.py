# pyrefly: ignore [missing-import]
from locust import HttpUser, task, between

class TaxiiUser(HttpUser):
    wait_time = between(1, 2)
    
    headers = {
        "Accept": "application/taxii+json;version=2.1",
        "Content-Type": "application/taxii+json;version=2.1"
    }

    stix_headers = {
        "Accept": "application/stix+json;version=2.1",
        "Content-Type": "application/taxii+json;version=2.1"
    }

    @task(1)
    def discover(self):
        self.client.get("/taxii2/", headers=self.headers, name="Discovery")

    @task(1)
    def api_root(self):
        self.client.get("/taxii2/phantomnet/", headers=self.headers, name="API Root")

    @task(2)
    def collections_list(self):
        self.client.get("/taxii2/phantomnet/collections/", headers=self.headers, name="Collections List")

    @task(5)
    def get_objects(self):
        # Using a known collection alias or ID (e.g. approved-playbooks)
        self.client.get("/taxii2/phantomnet/collections/approved-playbooks/objects/?limit=50", 
                        headers=self.stix_headers, name="Get Collection Objects")

    @task(3)
    def get_objects_paginated(self):
        self.client.get("/taxii2/phantomnet/collections/approved-playbooks/objects/?limit=20&next=20", 
                        headers=self.stix_headers, name="Get Objects Paginated")
