import time

import requests
from checklib import Status

from data import company, product


PORT = 8090


class Client:
    def __init__(self, checker):
        self.checker = checker
        self.session = requests.Session()
        self.base = f"http://{checker.host}:{PORT}"

    def request(self, method, path, status=Status.MUMBLE, **kwargs):
        for attempt in range(3):
            response = self.session.request(method, self.base + path, timeout=4, **kwargs)
            if response.status_code < 500 or attempt == 2:
                break
            time.sleep(0.3 * (attempt + 1))
        if response.status_code not in range(200, 300):
            self.checker.cquit(
                status,
                f"Unexpected HTTP status from {path}",
                f"{method} {path} returned HTTP {response.status_code}: {response.text[:200]}",
            )
        return response

    def json(self, method, path, status=Status.MUMBLE, **kwargs):
        response = self.request(method, path, status, **kwargs)
        return self.checker.get_json(response, f"Invalid JSON from {path}", status)

    def json_dict(self, method, path, status=Status.MUMBLE, **kwargs):
        data = self.json(method, path, status, **kwargs)
        self.checker.assert_eq(type(data), dict, f"Invalid object from {path}", status)
        return data

    def json_list(self, method, path, status=Status.MUMBLE, **kwargs):
        data = self.json(method, path, status, **kwargs)
        self.checker.assert_eq(type(data), list, f"Invalid list from {path}", status)
        return data

    def register_buyer(self, username, password):
        return self.json_dict("POST", "/api/register", json={"username": username, "password": password, "role": "buyer"})

    def register_seller(self, username, password, signature):
        seller = company()
        return self.json_dict("POST", "/api/register", json={
            "username": username,
            "password": password,
            "role": "seller",
            "company_name": seller["name"],
            "tax_id": seller["tax_id"],
            "signature": signature,
        })

    def login(self, username, password, status=Status.CORRUPT):
        data = self.json_dict("POST", "/api/login", status, json={"username": username, "password": password})
        self.checker.assert_eq(data.get("username"), username, "Service error", status)
        return data

    def create_product(self, cargo):
        item = product(cargo)
        result = self.json_dict("POST", "/api/products", json=item)
        self.checker.assert_eq(type(result.get("id")), int, "Service error")
        return result["id"], item

    def buy(self, product_id):
        result = self.json_dict("POST", f"/api/products/{product_id}/buy", json={})
        self.checker.assert_eq(type(result.get("id")), int, "Service error")
        return result

    def credit_promo(self):
        account = self.json_dict("GET", "/api/account")
        promo = account.get("promo")
        if promo and promo.get("code"):
            self.json("POST", "/api/promo/credit", json={"code": promo["code"]})

    def delivered_order(self, order_id, status=Status.MUMBLE):
        for _ in range(20):
            orders = self.json_list("GET", "/api/orders", status)
            order = next((item for item in orders if isinstance(item, dict) and item.get("id") == order_id), None)
            if order and order["status"] == "delivered":
                return order
            time.sleep(0.2)
        self.checker.cquit(status, "Service error", f"Order {order_id} is still pending")
