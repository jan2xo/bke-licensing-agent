from bke_licensing_agent.license_center import LicenseCenterController, Screen


class Agent:
    def connect(self): pass
    def login(self, credentials): self.credentials = credentials
    def login_with_license_key(self, key): self.key = key
    def discovered_products(self): return ["demo"]
    def activate(self, product): return {"status": "active"}
    def deactivate(self, product): pass
    def status(self, product): return {"status": "inactive"}
    def logout(self): pass
    def return_to_requesting_product(self, product): self.returned = product


def test_license_center_customer_flow_delegates_to_agent():
    agent = Agent()
    controller = LicenseCenterController(agent)
    assert controller.connect().screen is Screen.SIGN_IN
    assert controller.sign_in("credential-boundary").screen is Screen.PRODUCTS
    controller.select_product("demo")
    assert controller.activate().screen is Screen.STATUS
    controller.return_to_requesting_product()
    assert agent.returned == "demo"


def test_license_center_denial_is_an_error_screen_and_retry_is_supported():
    class Denied(Agent):
        def activate(self, product): raise RuntimeError("authorization_denied")
    controller = LicenseCenterController(Denied())
    controller.connect(); controller.sign_in("x"); controller.select_product("demo")
    assert controller.activate().screen is Screen.ERROR
    assert controller.retry_activation().screen is Screen.ERROR


def test_license_center_delegates_refresh_and_deactivation():
    agent = Agent()
    controller = LicenseCenterController(agent)
    controller.connect(); controller.select_product("demo")
    assert controller.refresh_license().screen is Screen.STATUS
    assert controller.deactivate_device().screen is Screen.STATUS
