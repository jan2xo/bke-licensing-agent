"""Thin License Center interaction layer; the Licensing Agent remains authoritative."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Screen(StrEnum):
    CONNECT = "connect"
    SIGN_IN = "sign_in"
    PRODUCTS = "products"
    ACTIVATION = "activation"
    STATUS = "status"
    ERROR = "error"


@dataclass(frozen=True)
class LicenseCenterState:
    screen: Screen = Screen.CONNECT
    connected: bool = False
    authenticated: bool = False
    products: tuple[Any, ...] = ()
    selected_product: Any | None = None
    status: Any | None = None
    error: str | None = None
    return_to_product: bool = False


class LicenseCenterController:
    """Maps customer actions to existing typed agent APIs; contains no license rules."""

    def __init__(self, agent: Any):
        self.agent = agent
        self.state = LicenseCenterState()

    def connect(self) -> LicenseCenterState:
        self.agent.connect()
        self.state = LicenseCenterState(screen=Screen.SIGN_IN, connected=True)
        return self.state

    def sign_in(self, credentials: Any) -> LicenseCenterState:
        self.agent.login(credentials)
        self.state = LicenseCenterState(screen=Screen.PRODUCTS, connected=True, authenticated=True,
                                        products=tuple(self.agent.discovered_products()))
        return self.state

    def enter_license_key(self, license_key: str) -> LicenseCenterState:
        self.agent.login_with_license_key(license_key)
        self.state = LicenseCenterState(screen=Screen.PRODUCTS, connected=True, authenticated=True,
                                        products=tuple(self.agent.discovered_products()))
        return self.state

    def select_product(self, product: Any) -> LicenseCenterState:
        self.state = LicenseCenterState(screen=Screen.ACTIVATION, connected=self.state.connected,
                                        authenticated=self.state.authenticated, products=self.state.products,
                                        selected_product=product)
        return self.state

    def activate(self) -> LicenseCenterState:
        try:
            status = self.agent.activate(self.state.selected_product)
            self.state = LicenseCenterState(screen=Screen.STATUS, connected=True, authenticated=True,
                products=self.state.products, selected_product=self.state.selected_product, status=status,
                return_to_product=True)
        except Exception as exc:
            self.state = LicenseCenterState(screen=Screen.ERROR, connected=self.state.connected,
                authenticated=self.state.authenticated, products=self.state.products,
                selected_product=self.state.selected_product, error=str(exc))
        return self.state

    def retry_activation(self) -> LicenseCenterState:
        return self.activate()

    def add_license(self) -> LicenseCenterState:
        try:
            status = self.agent.add_license(self.state.selected_product)
            self.state = LicenseCenterState(screen=Screen.STATUS, connected=True,
                authenticated=True, products=self.state.products,
                selected_product=self.state.selected_product, status=status,
                return_to_product=True)
        except Exception as exc:
            self.state = LicenseCenterState(screen=Screen.ERROR, connected=self.state.connected,
                authenticated=self.state.authenticated, products=self.state.products,
                selected_product=self.state.selected_product, error=str(exc))
        return self.state

    def list_licenses(self) -> tuple[Any, ...]:
        return tuple(self.agent.list_licenses(self.state.selected_product))

    def select_license(self, license_id: str) -> LicenseCenterState:
        try:
            status = self.agent.select_license(self.state.selected_product, license_id)
            self.state = LicenseCenterState(screen=Screen.STATUS, connected=True,
                authenticated=True, products=self.state.products,
                selected_product=self.state.selected_product, status=status,
                return_to_product=True)
        except Exception as exc:
            self.state = LicenseCenterState(screen=Screen.ERROR, connected=self.state.connected,
                authenticated=self.state.authenticated, products=self.state.products,
                selected_product=self.state.selected_product, error=str(exc))
        return self.state

    def remove_license(self, license_id: str) -> LicenseCenterState:
        try:
            self.agent.remove_license(self.state.selected_product, license_id)
            return self._status()
        except Exception as exc:
            self.state = LicenseCenterState(screen=Screen.ERROR, connected=self.state.connected,
                authenticated=self.state.authenticated, products=self.state.products,
                selected_product=self.state.selected_product, error=str(exc))
            return self.state

    def refresh_license(self) -> LicenseCenterState:
        return self._status()

    def deactivate_device(self) -> LicenseCenterState:
        return self.deactivate()

    def deactivate(self) -> LicenseCenterState:
        self.agent.deactivate(self.state.selected_product)
        return self._status()

    def logout(self) -> LicenseCenterState:
        self.agent.logout()
        self.state = LicenseCenterState(screen=Screen.SIGN_IN, connected=self.state.connected)
        return self.state

    def return_to_requesting_product(self) -> None:
        if self.state.return_to_product:
            self.agent.return_to_requesting_product(self.state.selected_product)

    def _status(self) -> LicenseCenterState:
        status = self.agent.status(self.state.selected_product)
        self.state = LicenseCenterState(screen=Screen.STATUS, connected=self.state.connected,
            authenticated=self.state.authenticated, products=self.state.products,
            selected_product=self.state.selected_product, status=status)
        return self.state
