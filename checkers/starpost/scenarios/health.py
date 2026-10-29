from checklib import rnd_password, rnd_string, rnd_username

from checklib import Status

from client import Client
from data import manifest, public_review
from scenarios.contract import fetch_own_contract
from scenarios.contract import verify as verify_contract


def check(checker):
    seller_name, seller_password = rnd_username(), rnd_password()
    buyer_name, buyer_password = rnd_username(), rnd_password()
    contract_signature = rnd_string(32)
    seller = Client(checker)
    seller.register_seller(seller_name, seller_password, contract_signature)
    product_id, item = seller.create_product(manifest())
    details = seller.json("GET", f"/api/products/{product_id}")
    checker.assert_eq(details["name"], item["name"], "Service error")
    document = fetch_own_contract(checker, seller, Status.MUMBLE)
    verify_contract(checker, document, contract_signature, Status.MUMBLE)

    buyer = Client(checker)
    buyer.register_buyer(buyer_name, buyer_password)
    account = buyer.json("GET", "/api/account")
    checker.assert_eq(account["promo"]["amount"], 100, "Service error")
    buyer.json("POST", "/api/promo/credit", json={"code": account["promo"]["code"]})
    buyer.json("POST", "/api/promo/invalidate", json={"code": account["promo"]["code"]})
    buyer.json("POST", "/api/cart", json={"product_id": product_id})
    cart = buyer.json("GET", "/api/cart")
    checker.assert_in(product_id, [row["id"] for row in cart], "Service error")
    checkout = buyer.json("POST", "/api/cart/checkout", json={})
    order = checkout["orders"][0]
    delivered = buyer.delivered_order(order["id"])
    checker.assert_in("Код грузового манифеста", delivered["cargo"], "Service error")
    message = public_review()
    buyer.json("POST", f"/api/orders/{order['id']}/review", json={"body": message, "rating": 5, "private": False})
    details = buyer.json("GET", f"/api/products/{product_id}")
    checker.assert_in(message, [row["body"] for row in details["reviews"]], "Service error")
    warehouse = Client(checker).json("GET", "/api/warehouse")
    checker.assert_eq(warehouse["status"], "online", "Service error")
