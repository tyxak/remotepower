"""SAML 2.0 SP (service-provider) helpers (v4.2.0 B1).

Thin wrapper over the vetted ``pysaml2`` library — we never hand-roll XML or
signature handling (XML signature-wrapping is an auth-bypass class; pysaml2 does
the verification). Both pysaml2 AND the ``xmlsec1`` system binary are required;
``available()`` returns False when either is missing and the API handlers in
api.py degrade gracefully (503) instead of crashing.

The SP is configured entirely from the RemotePower config dict (IdP entity-id /
SSO URL / x509 cert) — no on-disk pysaml2 config file. Outstanding AuthnRequest
IDs are tracked by the caller for InResponseTo / replay protection.

Security note: this still requires the mandatory pre-prod security review. The
authorization model (which IdP is trusted, attribute→username mapping, whether a
first-seen user is JIT-provisioned and with what role) is enforced by the caller
in api.py — this module only proves the assertion is authentic and fresh.
"""

import shutil

try:
    from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
    from saml2.config import SPConfig
    from saml2.client import Saml2Client
    from saml2.metadata import entity_descriptor
    _LIB = True
except Exception:  # library not installed → feature disabled, app still runs
    _LIB = False


def _xmlsec_path():
    return shutil.which('xmlsec1')


def available():
    """True only when BOTH pysaml2 and the xmlsec1 binary are present — pysaml2
    shells out to xmlsec1 for signature verification, so the lib alone is not
    enough to safely process a response."""
    return bool(_LIB and _xmlsec_path())


def _idp_metadata_xml(entity_id, sso_url, x509_cert):
    """Minimal IdP metadata document built from the three config fields, so the
    operator only pastes entity-id / SSO-URL / cert rather than a full XML blob.
    ``x509_cert`` is the base64 DER body (PEM header/footer stripped)."""
    cert = ''.join(x509_cert.split())  # strip whitespace/newlines
    for marker in ('-----BEGINCERTIFICATE-----', '-----ENDCERTIFICATE-----',
                   '-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'):
        cert = cert.replace(marker, '')
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="{_xml_attr(entity_id)}">'
        '<IDPSSODescriptor protocolSupportEnumeration='
        '"urn:oasis:names:tc:SAML:2.0:protocol">'
        '<KeyDescriptor use="signing"><KeyInfo '
        'xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data>'
        f'<X509Certificate>{cert}</X509Certificate>'
        '</X509Data></KeyInfo></KeyDescriptor>'
        '<SingleSignOnService '
        'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        f'Location="{_xml_attr(sso_url)}"/>'
        '</IDPSSODescriptor></EntityDescriptor>'
    )


def _xml_attr(s):
    return (str(s).replace('&', '&amp;').replace('"', '&quot;')
            .replace('<', '&lt;').replace('>', '&gt;'))


def _sp_config(rp_cfg, base_url):
    acs_url = base_url + '/api/saml/acs'
    sp_entity = rp_cfg.get('saml_sp_entity_id') or (base_url + '/api/saml/metadata')
    idp_xml = _idp_metadata_xml(
        rp_cfg.get('saml_idp_entity_id', ''),
        rp_cfg.get('saml_idp_sso_url', ''),
        rp_cfg.get('saml_idp_x509_cert', ''))
    settings = {
        'entityid': sp_entity,
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [(acs_url, BINDING_HTTP_POST)],
                },
                'allow_unsolicited': bool(rp_cfg.get('saml_allow_unsolicited')),
                'want_response_signed': True,
                'want_assertions_signed': True,
                'authn_requests_signed': False,
                'name_id_format': [
                    'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
                    'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                ],
            },
        },
        'metadata': {'inline': [idp_xml]},
        'allow_unknown_attributes': True,
        'xmlsec_binary': _xmlsec_path(),
    }
    conf = SPConfig()
    conf.load(settings)
    return conf


def metadata_xml(rp_cfg, base_url):
    """SP metadata XML the operator hands to their IdP. Generation does not need
    xmlsec1, so it works whenever the library is importable."""
    conf = _sp_config(rp_cfg, base_url)
    return str(entity_descriptor(conf))


def login_redirect(rp_cfg, base_url, relay_state='/'):
    """SP-initiated SSO: returns (redirect_url, request_id). Store request_id as
    an outstanding query so the ACS can enforce InResponseTo (replay)."""
    client = Saml2Client(config=_sp_config(rp_cfg, base_url))
    idp = rp_cfg.get('saml_idp_entity_id')
    req_id, info = client.prepare_for_authenticate(
        entityid=idp, relay_state=relay_state, binding=BINDING_HTTP_REDIRECT)
    redirect_url = dict(info['headers']).get('Location')
    return redirect_url, req_id


def parse_response(rp_cfg, base_url, saml_response_b64, outstanding):
    """Verify a POSTed SAMLResponse. ``outstanding`` maps request_id → came_from
    (the in-flight AuthnRequests); pysaml2 enforces InResponseTo against it.
    Returns {name_id, attributes}, or raises on any verification failure
    (signature, audience, expiry, replay)."""
    client = Saml2Client(config=_sp_config(rp_cfg, base_url))
    authn_response = client.parse_authn_request_response(
        saml_response_b64, BINDING_HTTP_POST, outstanding=outstanding)
    if authn_response is None:
        raise ValueError('SAML response did not validate')
    name_id = authn_response.get_subject()
    ava = authn_response.get_identity() or {}
    # pysaml2 returns each attribute as a list; flatten single values.
    attrs = {k: (v[0] if isinstance(v, list) and len(v) == 1 else v)
             for k, v in ava.items()}
    return {'name_id': name_id.text if name_id is not None else None,
            'attributes': attrs,
            'in_response_to': getattr(authn_response, 'in_response_to', None)}
