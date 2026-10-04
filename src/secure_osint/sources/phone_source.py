from typing import Any, Dict

import phonenumbers
from phonenumbers import PhoneNumberFormat, PhoneNumberType, carrier, geocoder
from phonenumbers.timezone import time_zones_for_number

from secure_osint.sources.base import BaseSource, SourceUnavailable
from secure_osint.sources.registry import register_source

# Mappa i tipi di libphonenumber a etichette stabili e leggibili.
LINE_TYPES: Dict[int, str] = {
    PhoneNumberType.MOBILE: 'mobile',
    PhoneNumberType.FIXED_LINE: 'fixed_line',
    PhoneNumberType.FIXED_LINE_OR_MOBILE: 'fixed_line_or_mobile',
    PhoneNumberType.VOIP: 'voip',
    PhoneNumberType.TOLL_FREE: 'toll_free',
    PhoneNumberType.PREMIUM_RATE: 'premium_rate',
    PhoneNumberType.SHARED_COST: 'shared_cost',
    PhoneNumberType.PERSONAL_NUMBER: 'personal_number',
    PhoneNumberType.PAGER: 'pager',
    PhoneNumberType.UAN: 'uan',
    PhoneNumberType.VOICEMAIL: 'voicemail',
}


@register_source('phone')
class PhoneSource(BaseSource):
    """Validazione telefonica 100% offline con libphonenumber (nessuna richiesta di rete).

    Estrae prefisso internazionale, regione, area geografica, operatore e tipo di linea. NON esegue
    alcuna verifica di registrazione su servizi terzi (niente WhatsApp/Telegram). Il numero (e164,
    international) è un identificativo di categoria 'network' nel PrivacyGuard: redatto di default nei
    report, mostrato solo con --keep-network. Non messo in cache: nessun costo di rete da risparmiare
    e nessun dato personale persistito su disco.

    ``formats`` lists the same number as E.164, international, national, RFC 3966 (``tel:``) and bare
    digits (country code + national number), offline via libphonenumber: the spellings to search for
    manually. Caveat: the regex-based PrivacyGuard catches the ``+``-prefixed forms, but not bare
    digits or every national layout; the report layer must redact those (see the xfail in test_phone).
    """

    cacheable = False
    # Nessun client HTTP: la fonte non tocca la rete.
    client = None

    def fetch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Query offline phone validation via libphonenumber and return the collected data.

        Args:
            params: Step parameters; always includes ``input`` (the target) and ``upstream``.

        Returns:
            A dict of results specific to this source.

        Raises:
            SourceUnavailable: Permanent failure (invalid input, 404, blocked, missing key).
            TransientSourceError: Temporary failure worth retrying (timeout, 429, 5xx).
        """
        raw = self.require_input(params)
        region = params.get('region') or None
        try:
            number = phonenumbers.parse(raw, region)
        except phonenumbers.NumberParseException as e:
            raise SourceUnavailable(f'Not a parseable phone number: {e}') from e

        line = geocoder.description_for_number(number, 'en') or None
        operator = carrier.name_for_number(number, 'en') or None
        e164 = phonenumbers.format_number(number, PhoneNumberFormat.E164)
        formats = {
            'e164': e164,
            'international': phonenumbers.format_number(number, PhoneNumberFormat.INTERNATIONAL),
            'national': phonenumbers.format_number(number, PhoneNumberFormat.NATIONAL),
            'rfc3966': phonenumbers.format_number(number, PhoneNumberFormat.RFC3966),
            # Country code + national number, no separators: the form many sites index and search.
            'digits': e164.lstrip('+'),
        }
        return {
            'valid': phonenumbers.is_valid_number(number),
            'possible': phonenumbers.is_possible_number(number),
            'country_code': number.country_code,
            'region': phonenumbers.region_code_for_number(number),
            'location': line,
            'carrier': operator,
            'line_type': LINE_TYPES.get(phonenumbers.number_type(number), 'unknown'),
            'e164': e164,
            'international': formats['international'],
            'timezone': list(time_zones_for_number(number)),
            'formats': formats,
        }
