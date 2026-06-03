const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const CERT_DIR = path.join(__dirname, '..', 'certs');

function getCertPaths() {
  return {
    privateKey: path.join(CERT_DIR, 'idp-private-key.pem'),
    certificate: path.join(CERT_DIR, 'idp-certificate.pem')
  };
}

function certsExist() {
  const { privateKey, certificate } = getCertPaths();
  return fs.existsSync(privateKey) && fs.existsSync(certificate);
}

function getCertificate() {
  const { certificate } = getCertPaths();
  return fs.readFileSync(certificate, 'utf-8');
}

function getCertificateBase64() {
  const cert = getCertificate();
  return cert
    .replace('-----BEGIN CERTIFICATE-----', '')
    .replace('-----END CERTIFICATE-----', '')
    .replace(/\s/g, '');
}

function getPrivateKey() {
  const { privateKey } = getCertPaths();
  return fs.readFileSync(privateKey, 'utf-8');
}

function buildSamlResponse({ user, spConfig, hostname, inResponseTo }) {
  const now = new Date();
  const fiveMinLater = new Date(now.getTime() + 5 * 60 * 1000);
  const eightHoursLater = new Date(now.getTime() + 8 * 60 * 60 * 1000);

  let nameId = user.email;
  let nameIdFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';

  if (spConfig.name_id_format === 'persistent' && user.immutable_id) {
    nameId = user.immutable_id;
    nameIdFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
  }

  const responseId = '_' + uuidv4();
  const assertionId = '_' + uuidv4();
  const sessionIndex = '_' + uuidv4();
  const issueInstant = now.toISOString();
  const notBefore = new Date(now.getTime() - 5 * 60 * 1000).toISOString();
  const notOnOrAfter = fiveMinLater.toISOString();
  const sessionNotOnOrAfter = eightHoursLater.toISOString();

  // Build attributes
  const attrs = [];
  attrs.push(`<saml:Attribute Name="IDPEmail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">${user.email}</saml:AttributeValue></saml:Attribute>`);
  if (user.first_name) {
    attrs.push(`<saml:Attribute Name="user.firstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">${user.first_name}</saml:AttributeValue></saml:Attribute>`);
  }
  if (user.last_name) {
    attrs.push(`<saml:Attribute Name="user.lastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">${user.last_name}</saml:AttributeValue></saml:Attribute>`);
  }

  let inResponseToAttr = '';
  if (inResponseTo) {
    inResponseToAttr = ` InResponseTo="${inResponseTo}"`;
  }

  const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${responseId}" Version="2.0" IssueInstant="${issueInstant}" Destination="${spConfig.acs_url}"${inResponseToAttr}>
  <saml:Issuer>https://${hostname}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="${assertionId}" Version="2.0" IssueInstant="${issueInstant}">
    <saml:Issuer>https://${hostname}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="${nameIdFormat}">${nameId}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="${sessionNotOnOrAfter}" Recipient="${spConfig.acs_url}"${inResponseToAttr}/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">
      <saml:AudienceRestriction><saml:Audience>${spConfig.entity_id}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${issueInstant}" SessionNotOnOrAfter="${sessionNotOnOrAfter}" SessionIndex="${sessionIndex}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      ${attrs.join('\n      ')}
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;

  // Sign the assertion
  const { SignedXml } = require('xml-crypto');
  const sig = new SignedXml();
  sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';

  sig.addReference({
    xpath: "//*[local-name(.)='Assertion']",
    transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
  });

  sig.privateKey = getPrivateKey();
  sig.publicCert = getCertificate();
  sig.computeSignature(xml, {
    prefix: 'ds',
    location: { reference: "//*[local-name(.)='Issuer' and ancestor::*[local-name(.)='Assertion']]", action: 'after' }
  });

  return sig.getSignedXml();
}

function parseAuthnRequest(samlRequest) {
  try {
    const inflated = require('zlib').inflateRawSync(Buffer.from(samlRequest, 'base64'));
    const xml = inflated.toString('utf-8');
    const idMatch = xml.match(/ID="([^"]+)"/);
    const issuerMatch = xml.match(/<(?:saml[p]?:)?Issuer[^>]*>([^<]+)<\//);
    return {
      id: idMatch ? idMatch[1] : null,
      issuer: issuerMatch ? issuerMatch[1] : null,
      raw: xml
    };
  } catch (e) {
    try {
      const xml = Buffer.from(samlRequest, 'base64').toString('utf-8');
      const idMatch = xml.match(/ID="([^"]+)"/);
      const issuerMatch = xml.match(/<(?:saml[p]?:)?Issuer[^>]*>([^<]+)<\//);
      return {
        id: idMatch ? idMatch[1] : null,
        issuer: issuerMatch ? issuerMatch[1] : null,
        raw: xml
      };
    } catch (e2) {
      return { id: null, issuer: null, raw: null };
    }
  }
}

function generateMetadata(hostname) {
  const cert = getCertificateBase64();
  return `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://${hostname}">
  <IDPSSODescriptor WantAuthnRequestsSigned="false"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>${cert}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://${hostname}/saml/sso"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://${hostname}/saml/sso"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://${hostname}/saml/slo"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;
}

module.exports = {
  buildSamlResponse,
  parseAuthnRequest,
  generateMetadata,
  getCertificate,
  getCertificateBase64,
  getPrivateKey,
  certsExist,
  getCertPaths
};
