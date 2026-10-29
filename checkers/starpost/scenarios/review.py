from checklib import Status, rnd_password, rnd_string, rnd_username

from client import Client


def put(checker, flag):
    seller_name, seller_password = rnd_username(), rnd_password()
    buyer_name, buyer_password = rnd_username(), rnd_password()
    seller = Client(checker)
    seller.register_seller(seller_name, seller_password, "SIGN-" + rnd_string(24))
    product_id, _ = seller.create_product("sealed cargo")
    buyer = Client(checker)
    buyer.register_buyer(buyer_name, buyer_password)
    buyer.credit_promo()
    order = buyer.buy(product_id)
    buyer.delivered_order(order["id"])
    review = buyer.json_dict("POST", f"/api/orders/{order['id']}/review", json={"body": flag, "rating": 5, "private": True})
    checker.assert_eq(type(review.get("id")), int, "Service error")

    response = seller.json_dict("GET", "/api/seller/reviews")
    checker.assert_eq(type(response.get("reviews")), list, "Service error")
    stored = response["reviews"]
    next_cursor = response.get("next_cursor")

    pages_checked = 1
    stored_review = next((item for item in stored if isinstance(item, dict) and item.get("id") == review["id"]), None)
    while not stored_review and next_cursor and pages_checked < 10:
        response = seller.json_dict("GET", f"/api/seller/reviews?cursor={next_cursor}")
        checker.assert_eq(type(response.get("reviews")), list, "Service error")
        stored += response["reviews"]
        next_cursor = response.get("next_cursor")
        pages_checked += 1
        stored_review = next((item for item in stored if isinstance(item, dict) and item.get("id") == review["id"]), None)

    checker.assert_neq(stored_review, None, "Service error")
    checker.assert_eq(stored_review.get("body"), flag, "Service error")
    checker.assert_eq(stored_review.get("is_private"), True, "Service error")
    return str(product_id), [seller_name, seller_password, review["id"]]


def get(checker, state, flag):
    client = Client(checker)
    client.login(state[0], state[1])

    response = client.json_dict("GET", "/api/seller/reviews", Status.CORRUPT)
    checker.assert_eq(type(response.get("reviews")), list, "Service error", Status.CORRUPT)
    reviews = response["reviews"]
    next_cursor = response.get("next_cursor")

    target_id = state[2]
    pages_checked = 1
    review = next((item for item in reviews if isinstance(item, dict) and item.get("id") == target_id), None)
    while not review and next_cursor and pages_checked < 10:
        response = client.json_dict("GET", f"/api/seller/reviews?cursor={next_cursor}", Status.CORRUPT)
        checker.assert_eq(type(response.get("reviews")), list, "Service error", Status.CORRUPT)
        reviews = response["reviews"]
        next_cursor = response.get("next_cursor")
        pages_checked += 1
        review = next((item for item in reviews if isinstance(item, dict) and item.get("id") == target_id), None)

    checker.assert_neq(review, None, "Service error", Status.CORRUPT)
    checker.assert_eq(type(review.get("body")), str, "Service error", Status.CORRUPT)
    checker.assert_in(flag, review.get("body", ""), "Service error", Status.CORRUPT)
    checker.assert_eq(review.get("is_private"), True, "Service error", Status.CORRUPT)
