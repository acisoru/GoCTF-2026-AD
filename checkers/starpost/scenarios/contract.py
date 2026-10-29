from checklib import Status, rnd_password, rnd_username

from client import Client


def verify(checker, document, signature, status):
    checker.assert_in("application/pdf", document.headers.get("Content-Type", ""), "Service error", status)
    checker.assert_neq(document.content, b"", "Service error", status)
    if signature.encode() not in document.content:
        checker.cquit(status, "Service error", "Expected signature is absent from PDF")


def fetch_own_contract(checker, client, status):
    profile = client.json_dict("GET", "/api/me", status)
    filename = profile.get("contract_file")
    if not isinstance(filename, str) or not filename.startswith("contract-"):
        checker.cquit(status, "Service error", f"api/me returned contract_file={filename!r}")
    return client.request("GET", f"/api/contract?file={filename}", status)


def put(checker, flag):
    seller_name, seller_password = rnd_username(), rnd_password()
    client = Client(checker)
    client.register_seller(seller_name, seller_password, flag)
    document = fetch_own_contract(checker, client, Status.MUMBLE)
    verify(checker, document, flag, Status.MUMBLE)
    return seller_name, [seller_name, seller_password]


def get(checker, state, flag):
    client = Client(checker)
    client.login(state[0], state[1])
    document = fetch_own_contract(checker, client, Status.CORRUPT)
    verify(checker, document, flag, Status.CORRUPT)
