from locust import HttpUser, between, task


class Shopper(HttpUser):
    wait_time = between(0.5, 1.5)

    @task(5)
    def browse(self):
        self.client.get("/products")

    @task(2)
    def home(self):
        self.client.get("/")

    @task(1)
    def slow(self):
        self.client.get("/slow")

    @task(1)
    def flaky(self):
        self.client.get("/flaky")
