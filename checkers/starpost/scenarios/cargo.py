from checklib import Status, rnd_password, rnd_username

from client import Client


def put(checker, flag):
    seller_name, seller_password = rnd_username(), rnd_password()
    buyer_name, buyer_password = rnd_username(), rnd_password()
    seller = Client(checker)
    seller.register_seller(seller_name, seller_password, "SIGN-" + rnd_password())
    product_id, _ = seller.create_product(flag)
    buyer = Client(checker)
    buyer.register_buyer(buyer_name, buyer_password)
    buyer.credit_promo()
    order = buyer.buy(product_id)
    delivered = buyer.delivered_order(order["id"])
    checker.assert_eq(type(delivered.get("cargo")), str, "Service error")
    checker.assert_in(flag, delivered.get("cargo", ""), "Service error")
    return str(product_id), [buyer_name, buyer_password, order["id"]]


def get(checker, state, flag):
    client = Client(checker)
    client.login(state[0], state[1])
    orders = client.json_list("GET", "/api/orders", Status.CORRUPT)
    order = next((item for item in orders if isinstance(item, dict) and item.get("id") == state[2]), None)
    checker.assert_neq(order, None, "Service error", Status.CORRUPT)
    checker.assert_eq(order.get("cargo"), flag, "Service error", Status.CORRUPT)
