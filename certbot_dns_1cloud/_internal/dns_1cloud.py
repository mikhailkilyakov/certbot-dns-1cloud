import logging
import requests
from typing import Any, Callable, Optional

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for 1cloud

    This Authenticator uses the 1cloud API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using 1cloud for DNS).'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 120) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='1cloud credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to responsd to a dns-01 challenge using ' + \
               'the 1cloud API.'

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            '1cloud credentials INI file',
            {
                'token': '1cloud API token'
            }
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_1cloud_client().add_txt_record(validation_name, validation)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_1cloud_client().del_txt_record(validation_name, validation)

    def _get_1cloud_client(self) -> '_1CloudClient':
        return _1CloudClient(self.credentials.conf('token'))


class DomainNotFoundError(BaseException):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)


class RecordNotFoundError(BaseException):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)


class _1CloudClient(object):
    """
    1Cloud API Client Wrapper
    """

    def __init__(self, token) -> None:
        self._token = token

    def add_txt_record(self, record_name, record_value):
        """
        Creates a TXT with given record_name and record_value
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_value: The record value
        :raises certbot.errors.PluginError: if an error occurs communicating with the 1cloud API
        """
        try:
            parsed = self._split_record_name(record_name)
            domain_id = self._load_domain_info(parsed['domain'])['ID']

            response = requests.post('https://api.1cloud.ru/dns/recordtxt', json={
                'DomainId': domain_id,
                'Name': parsed['subdomain'],
                'Text': record_value,
                'TTL': '1'
            }, headers=self._create_headers())
            response.raise_for_status()

        except requests.RequestException as e:
            logger.error('Encountered error adding TXT record: %d %s', e, e)
            raise errors.PluginError(
                'Error communicating with 1cloud API: {0}'.format(e))
        except DomainNotFoundError as e:
            logger.error('Encountered error adding TXT record: %d %s', e, e)
            raise errors.PluginError(
                'Error communicating with 1cloud API: {0}'.format(e))

    def del_txt_record(self, record_name, record_value):
        """
        Creates a TXT with given record_name and record_value
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_value: The record value
        :raises certbot.errors.PluginError: if an error occurs communicating with the 1cloud API
        """
        try:
            parsed = self._split_record_name(record_name)
            domain_info = self._load_domain_info(parsed['domain'])
            text_1cloud_value = '"' + record_value + '"'
            for record in domain_info['LinkedRecords']:
                if record['TypeRecord'] == 'TXT' and record['HostName'] == record_name + '.' and record['Text'].strip() == text_1cloud_value:
                    record_id = record['ID']
                    domain_id = domain_info['ID']
                    response = requests.delete(
                        'https://api.1cloud.ru/dns/{0}/{1}'.format(domain_id, record_id), headers=self._create_headers())
                    response.raise_for_status()
                    return

            raise RecordNotFoundError()
        except requests.RequestException as e:
            logger.error('Encountered error removing TXT record: %d %s', e, e)
            raise errors.PluginError(
                'Error communicating with 1cloud API: {0}'.format(e))
        except RecordNotFoundError as e:
            logger.error('Encountered error removing TXT record: %d %s', e, e)
            raise errors.PluginError(
                'Error communicating with 1cloud API: {0}'.format(e))
        except DomainNotFoundError as e:
            logger.error('Encountered error removing TXT record: %d %s', e, e)
            raise errors.PluginError(
                'Error communicating with 1cloud API: {0}'.format(e))

    def _create_headers(self):
        return {
            'Authorization': 'Bearer {0}'.format(self._token)
        }

    @classmethod
    def _split_record_name(cls, record_name):
        pieces = record_name.split('.')
        return {
            'domain': '.'.join(pieces[-2:]),
            'subdomain': '.'.join(pieces[:-2])
        }

    def _load_domain_info(self, domain):
        response = requests.get(
            'https://api.1cloud.ru/dns', headers=self._create_headers())

        response.raise_for_status()
        data = response.json()
        for info in data:
            if info['Name'] == domain:
                return info

        raise DomainNotFoundError()
