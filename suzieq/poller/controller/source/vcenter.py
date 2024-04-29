"""Netbox module

This module contains the methods to connect with a Netbox REST server
and retrieve the devices inventory

Classes:
    Netbox: this class dinamically retrieve the inventory from Netbox
"""
# pylint: disable=no-name-in-module
# pylint: disable=no-self-argument

import asyncio
import logging
import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from pydantic import BaseModel, validator, Field

import aiohttp
from suzieq.poller.controller.inventory_async_plugin import \
    InventoryAsyncPlugin
from suzieq.poller.controller.source.base_source import Source, SourceModel
from suzieq.shared.utils import get_sensitive_data
from suzieq.shared.exceptions import InventorySourceError, SensitiveLoadError

_DEFAULT_PORTS = {'http': 80, 'https': 443}

logger = logging.getLogger(__name__)


class VcenterServerModel(BaseModel):
    """Model containing data to connect with vcenter server
    """
    host: str
    port: str

    class Config:
        """pydantic configuration
        """
        extra = 'forbid'


class VcenterSourceModel(SourceModel):
    """ Vcenter source validation model
    """
    username: str
    password: str
    period: Optional[int] = Field(default=3600)
    ssl_verify: Optional[bool] = Field(alias='ssl-verify')
    server: Union[str, VcenterServerModel] = Field(alias='url')
    run_once: Optional[bool] = Field(default=False, alias='run_once')

    @validator('server', pre=True)
    def validate_and_set(cls, url, values):
        """Validate the field 'url' and set the correct parameters
        """
        if isinstance(url, str):
            url_data = urlparse(url)
            host = url_data.hostname
            if not host:
                raise ValueError(f'Unable to parse hostname {url}')
            port = url_data.port or _DEFAULT_PORTS.get("https")
            if not port:
                raise ValueError(f'Unable to parse port {url}')
            server = VcenterServerModel(host=host, port=port)
            ssl_verify = values['ssl_verify']
            if ssl_verify is None:
                ssl_verify = True
            values['ssl_verify'] = ssl_verify
            return server
        elif isinstance(url, VcenterServerModel):
            return url
        else:
            raise ValueError('Unknown input type')

    @validator('password')
    def validate_password(cls, password):
        """checks if the password can be load as sensible data
        """
        try:
            if password == 'ask':
                return password
            return get_sensitive_data(password)
        except SensitiveLoadError as e:
            raise ValueError(e)

class Vcenter(Source, InventoryAsyncPlugin):
    """This class is used to dynamically retrieve the inventory from Vcenter
    """

    def __init__(self, config_data: dict, validate: bool = True) -> None:
        self._status = 'init'
        self._session: aiohttp.ClientSession = None
        self._session_token = None
        self._server: VcenterServerModel = None

        super().__init__(config_data, validate)

    @classmethod
    def get_data_model(cls):
        return VcenterSourceModel

    def _load(self, input_data):
        # load the server class from the dictionary
        if not self._validate:
            input_data['server'] = VcenterServerModel.construct(
                **input_data.pop('url', {}))
            input_data['ssl_verify'] = input_data.pop('ssl-verify', False)
        super()._load(input_data)
        if self._data.password == 'ask':
            self._data.password = get_sensitive_data(
                'ask', f'{self.name} Insert vcenter password: '
            )
        self._server = self._data.server
        if not self._auth:
            raise InventorySourceError(f"{self.name} Vcenter must have an "
                                       "'auth' set in the 'namespaces' section"
                                       )

    def _init_session(self, headers: dict):
        """Initialize the session property

        Args:
            headers ([dict]): headers to initialize the session
        """
        if not self._session:
            self._session = aiohttp.ClientSession(
                headers=headers,
                connector=aiohttp.TCPConnector(ssl=self._data.ssl_verify)
            )

    def _fetch_session_token(self):
        """Log in to VCenter and fetch a session token."""
        auth_url = f'https://{self._server.host}:{self._server.port}/api/session'
        auth_creds = HTTPBasicAuth(self._data.username, self._data.password)
        try:
            response = requests.post(auth_url, auth=auth_creds, verify=self._data.ssl_verify)
            response.raise_for_status()
            self._session_token = response.json()
        except RequestException as e:
            raise InventorySourceError(f"Failed to authenticate with VCenter to obtain session token: {str(e)}")

    def _token_auth_header(self) -> Dict:
        """Generate the token authorization header

        Returns:
            Dict: token authorization header
        """
        if not self._session_token:
            self._fetch_session_token()
        return {'vmware-api-session-id': self._session_token}

    def _get_url_list(self) -> List[str]:
        """Return the list of requests to execute

        Returns:
            List[str]: list of urls
        """
        urls = [
            f'https://{self._server.host}:{self._server.port}/api/vcenter/vm'
        ]
        return urls

    async def get_inventory_list(self) -> List:
        """Contact vcenter to retrieve VMs.

        Raises:
            RuntimeError: Unable to connect to the REST server

        Returns:
            List: inventory list
        """
        if not self._session:
            headers = self._token_auth_header()
            self._init_session(headers)
        # Make a map by key of each VM id along with a name.
        vms = {}
        try:
            for url in self._get_url_list():
                logger.debug(f"Vcenter: Retrieving url '{url}'")
                url_vms = await self._get_devices(url)
                vms.update({vm['vm']: vm['name'] for vm in url_vms
                                if vm.get('vm') is not None})
        except Exception as e:
            raise InventorySourceError(f'{self.name}: error while '
                                       f'getting devices: {e}')

        logger.info(
            f'Vcenter: Retrieved inventory list of {len(vms)} vms')
        return list(vms.keys())

    async def _get_devices(self, url: str) -> List:
        """Retrieve vm from vcenter over <url>

        Args:
            url (str): devices url

        Raises:
            RuntimeError: Response error

        Returns:
            List: returns the list of vms
        """
        async with self._session.get(url) as response:
            if int(response.status) == 200:
                res = await response.json()
                return res
            else:
                raise InventorySourceError(
                    f'{self.name}: error in inventory get '
                    f'{await response.text()}')

    def parse_inventory(self, inventory_list: list) -> Dict:
        """parse the raw inventory collected from the server and generates
           a new inventory with only the required informations

        Args:
            raw_inventory (list): raw inventory received from the server

        Returns:
            List[Dict]: a list containing the inventory
        """
        inventory = {}

        for device in inventory_list:
            namespace = self._namespace
            address = f'{self._server.host}'
            inventory[f'{namespace}.{address}'] = {
                'address': address,
                'namespace': namespace,
                'hostname': address,
                'vm_id': device,
            }

        logger.info(f'Vcenter: Acting on inventory of {len(inventory)} devices')
        return inventory

    async def _execute(self):
        while True:
            inventory_list = await self.get_inventory_list()
            logger.debug(f'Received vcenter inventory from '
                f'https://{self._server.host}:{self._server.port}')
            tmp_inventory = self.parse_inventory(inventory_list)
            # Write the inventory and remove the tmp one
            self.set_inventory(tmp_inventory)

            if self._run_once:
                break

            await asyncio.sleep(self._data.period)

    async def _stop(self):
        if self._session:
            await self._session.close()
