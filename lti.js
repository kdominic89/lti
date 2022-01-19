const crypto  = require('crypto');
const { URL } = require('url');


module.exports = (function() {
    'use strict';
    
    class Rfc3986 {
        static encode(str) {
            if (typeof str === 'number' || typeof str === 'boolean') {
                str = str.toString();
            }
            return typeof str === 'string' ? encodeURIComponent(str).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16)}`) : '';
        }
    
        static decode(str) {
            return typeof str === 'string' ? decodeURIComponent(str) : '';
        }
    }
    
    class OAuthSignature {
        constructor({ method, url, body, query }) {
            Object.defineProperties(this, {
                method: { enumerable: true, value: method.toUpperCase()   },
                url:    { enumerable: true, value: Rfc3986.encode(url)    },
                body:   { enumerable: true, value: this._normalize(body)  },
                query:  { enumerable: true, value: this._normalize(query) },
            });
        }
    
        _normalize(params) {
            const out = [];
    
            if (params === null || typeof params !== 'object') {
                return out;
            }
    
            for (const [key, value] of Object.entries(params)) {
                if (key === 'oauth_signature') {
                    continue;
                }
        
                if (Array.isArray(value)) {
                    value.sort().forEach((val) => out.push(`${key}=${Rfc3986.encode(val)}`));
                }
                else {
                    out.push(`${key}=${Rfc3986.encode(value)}`);
                }
            }
            return out;
        }
    
        buildBase() {
            const parameters = Rfc3986.encode(this.body.concat(this.query).sort().join('&'));
            return `${this.method}&${this.url}&${parameters}`;
        }
    
        buildSignature({ secret, token='', encode=false }) {
            secret = !!encode ? Rfc3986.encode(secret) : secret;
            token  = typeof token === 'string' ? token : '';
    
            return crypto.createHmac('sha1', `${secret}&${token}`).update(this.buildBase()).digest('base64');
        }
    
        isValid(oauth_signature, signatureOption) {
            return oauth_signature === this.buildSignature(signatureOption);
        }
    
        static VERSION = '1.0';
    }

    const NONCE = new Map();

    const LTI_PROVIDER_VALID   = Symbol('valid');
    const LTI_PROVIDER_ERROR   = Symbol('error');
    const LTI_PROVIDER_BODY    = Symbol('body');
    const LTI_PROVIDER_DATA    = Symbol('data');
    const LTI_PROVIDER_USER    = Symbol('user');
    const LTI_PROVIDER_CONTEXT = Symbol('context');
    const LTI_PROVIDER_ROLE    = Symbol('role');

    class LtiProvider {
        constructor(consumerKey, consumerSecret, encodeSecret=false) {
            Object.defineProperties(this, {
                consumerKey:    { enumerable: true,  value: consumerKey    },
                consumerSecret: { enumerable: false, value: consumerSecret },
                encodeSecret:   { enumerable: true,  value: encodeSecret   },
    
                [LTI_PROVIDER_VALID]:   { value: false, writable: true },
                [LTI_PROVIDER_ERROR]:   { value: null,  writable: true },
                [LTI_PROVIDER_BODY]:    { value: {},    writable: true },
                [LTI_PROVIDER_DATA]:    { value: {},    writable: true },
                [LTI_PROVIDER_USER]:    { value: { id: null, name: null } },
                [LTI_PROVIDER_CONTEXT]: { value: { id: null, label: null, title: null }, writable: true },
                [LTI_PROVIDER_ROLE]:    { value: {
                    admin:      null,
                    instructor: null,
                    manager:  null,
                    alumni:   null,
                    observer: null,
                    mentor:   null,
                    student:  null,
                    member:   null,
                    guest:    null,
                    none:     null,
                    other:    null,
                    contentDeveloper:   null,
                    prospectiveStudent: null,
                    teachingAssistant:   null,
                }, writable: true}
            });
        }
    
        get valid() {
            return this[LTI_PROVIDER_VALID];
        }
    
        get error() {
            return this[LTI_PROVIDER_ERROR];
        }
    
        get body() {
            return this.valid ? { ...this[LTI_PROVIDER_BODY] } : {};
        }
    
        get data() {
            return this.valid ? { ...this[LTI_PROVIDER_DATA] } : {};
        }
    
        get userId() {
            return this.valid ? this[LTI_PROVIDER_USER].id : null;
        }
    
        get userName() {
            return this.valid ? this[LTI_PROVIDER_USER].name : null;
        }
    
        get contextId() {
            return this.valid ? this[LTI_PROVIDER_CONTEXT].id : null;
        }
    
        get contextLabel() {
            return this.valid ? this[LTI_PROVIDER_CONTEXT].label : null;
        }
    
        get contextTitle() {
            return this.valid ? this[LTI_PROVIDER_CONTEXT].title : null;
        }
    
        get admin() {
            return this[LTI_PROVIDER_ROLE].admin;
        }
    
        get instructor() {
            return this[LTI_PROVIDER_ROLE].instructor;
        }
    
        get manager() {
            return this[LTI_PROVIDER_ROLE].manager;
        }
    
        get alumni() {
            return this[LTI_PROVIDER_ROLE].alumni;
        }
    
        get observer() {
            return this[LTI_PROVIDER_ROLE].observer;
        }
    
        get mentor() {
            return this[LTI_PROVIDER_ROLE].mentor;
        }
    
        get student() {
            return this[LTI_PROVIDER_ROLE].student;
        }
    
        get member() {
            return this[LTI_PROVIDER_ROLE].member;
        }
    
        get guest() {
            return this[LTI_PROVIDER_ROLE].guest;
        }
    
        get none() {
            return this[LTI_PROVIDER_ROLE].none;
        }
    
        get other() {
            return this[LTI_PROVIDER_ROLE].other;
        }
    
        get contentDeveloper() {
            return this[LTI_PROVIDER_ROLE].contentDeveloper;
        }
    
        get prospectiveStudent() {
            return this[LTI_PROVIDER_ROLE].prospectiveStudent;
        }
    
        get teachingAssistant() {
            return this[LTI_PROVIDER_ROLE].teachingAssistant;
        }
        
        // https://www.imsglobal.org/wiki/step-2-valid-lti-launch-request
        validateRequest(req) {
            this[LTI_PROVIDER_VALID] = false;
            this[LTI_PROVIDER_ERROR] = null;
    
            const { method, body } = req;
    
            if (!LtiProvider.isValidMessage(method, body)) {
                this[LTI_PROVIDER_ERROR] = new Error('Invalid LTI launch request');
                return this;
            }
            const { oauth_callback, oauth_consumer_key, oauth_nonce, oauth_signature, oauth_signature_method, oauth_timestamp, oauth_version  } = body;
    
            // not used by LTI so should always have a value of about:blank
            //if (oauth_callback !== 'about:blank') {}
    
            if (oauth_consumer_key !== this.consumerKey) {
                this[LTI_PROVIDER_ERROR] = new Error('Different consumer keys');
                return this;
            }
    
            if (!oauth_nonce) {
                this[LTI_PROVIDER_ERROR] = new Error(`'oauth_nonce' required`);
                return this;
            }
    
            if (!oauth_signature) {
                this[LTI_PROVIDER_ERROR] = new Error(`'oauth_signature' required`);
                return this;
            }
    
            if (oauth_signature_method !== 'HMAC-SHA1') {
                this[LTI_PROVIDER_ERROR] = new Error(`Invalid 'oauth_signature_method' method (${oauth_signature_method})`);
                return this;
            }
    
            if (!oauth_timestamp) {
                this[LTI_PROVIDER_ERROR] = new Error(`'oauth_timestamp' required`);
                return this;
            }
            let timestamp = Number.parseInt(oauth_timestamp);
    
            if (!Number.isFinite(timestamp)) {
                this[LTI_PROVIDER_ERROR] = new Error(`'oauth_timestamp' is not a number`);
                return this;
            }
            timestamp *= 1000;
    
            if (oauth_version !== OAuthSignature.VERSION) {
                this[LTI_PROVIDER_ERROR] = new Error(`Invalid oauth version (${oauth_version})`);
                return this;
            }
            this._clearNonce();
    
            if (NONCE.has(oauth_nonce)) {
                this[LTI_PROVIDER_ERROR] = new Error(`Nonce already seen`);
                return this;
            }
    
            if (this._isExpired(timestamp)) {
                this[LTI_PROVIDER_ERROR] = new Error(`'oauth_timestamp' expired`);
                return this;
            }
    
            const originalHost   = new URL(req.get('origin') ?? req.get('host'));
            const originalUrl    = new URL(req.originalUrl ?? req.url, originalHost);
            const oauthSignature = new OAuthSignature({ method, url: originalUrl.href, body });
    
            if (!oauthSignature.isValid(oauth_signature, { secret: this.consumerSecret, encode: this.encodeSecret })) {
                this[LTI_PROVIDER_ERROR] = new Error('Invalid LTI Signature');
                return this;
            }
            NONCE.set(oauth_nonce, timestamp);
            this[LTI_PROVIDER_VALID] = true;
    
            return this._parse(body);
        }
    
        _clearNonce() {
            const iterator = NONCE.entries();
            for (const [key, value] of iterator) {
                if (value <= Date.now()) {
                    NONCE.delete(key);
                }
            }
            return this;
        }
    
        _isExpired(timestamp) {
            return (Date.now() - timestamp) > LtiProvider.EXPIRE_TIME || (timestamp - Date.now()) > LtiProvider.EXPIRE_TIME;
        }
    
        _parse(body) {
            this[LTI_PROVIDER_BODY] = body;
            this[LTI_PROVIDER_DATA] = {};
    
            for (const [key, value] of Object.entries(body)) {
                if (/^oauth_/.test(key)) {
                    continue;
                }
                this[LTI_PROVIDER_DATA][key] = value;
            }
            
            if (typeof this[LTI_PROVIDER_DATA].roles === 'string') {
                this[LTI_PROVIDER_DATA].roles = this[LTI_PROVIDER_DATA].roles.split(',');
            }
    
            this[LTI_PROVIDER_USER].id   = this[LTI_PROVIDER_DATA].user_id;
            this[LTI_PROVIDER_USER].name = this[LTI_PROVIDER_DATA].ext_user_username ?? this[LTI_PROVIDER_DATA].lis_person_contact_email_primary;
    
            this[LTI_PROVIDER_CONTEXT].id    = this[LTI_PROVIDER_DATA].context_id;
            this[LTI_PROVIDER_CONTEXT].label = this[LTI_PROVIDER_DATA].context_label;
            this[LTI_PROVIDER_CONTEXT].title = this[LTI_PROVIDER_DATA].context_title;
    
            this[LTI_PROVIDER_ROLE].admin      = this._hasRole('Administrator');
            this[LTI_PROVIDER_ROLE].instructor = this._hasRole('Instructor') || this._hasRole('Faculty') || this._hasRole('Staff');
            this[LTI_PROVIDER_ROLE].manager    = this._hasRole('Manager');
            this[LTI_PROVIDER_ROLE].alumni     = this._hasRole('Alumni');
            this[LTI_PROVIDER_ROLE].observer   = this._hasRole('Observer');
            this[LTI_PROVIDER_ROLE].mentor     = this._hasRole('Mentor');
            this[LTI_PROVIDER_ROLE].student    = this._hasRole('Learner') || this._hasRole('Student');
            this[LTI_PROVIDER_ROLE].member     = this._hasRole('Member');
            this[LTI_PROVIDER_ROLE].guest      = this._hasRole('Guest')
            this[LTI_PROVIDER_ROLE].none       = this._hasRole('None');
            this[LTI_PROVIDER_ROLE].other      = this._hasRole('Other');
            this[LTI_PROVIDER_ROLE].contentDeveloper   = this._hasRole('ContentDeveloper'),
            this[LTI_PROVIDER_ROLE].prospectiveStudent = this._hasRole('ProspectiveStudent');
            this[LTI_PROVIDER_ROLE].teachingAssistant  = this._hasRole('TeachingAssistant');
    
            return this;
        }
    
        _hasRole(role) {
            const regex = new RegExp(`^(urn:lti:(sys|inst)?role:ims/lis/)?${role}(/.+)?$`, 'i');
            
            return Array.isArray(this[LTI_PROVIDER_DATA].roles) && this[LTI_PROVIDER_DATA].roles.some((r) => regex.test(r));
        }
        
        static MESSAGE_TYPE  = 'basic-lti-launch-request';
        static VERSION       = 'LTI-1p0';
        static EXPIRE_TIME   = 300000;
    
        // https://www.imsglobal.org/wiki/step-1-lti-launch-request
        static isValidMessage(method, body) {
            if (typeof method !== 'string' || method.toUpperCase() !== 'POST' || typeof body !== 'object') {
                return false;
            }
            const { lti_message_type, lti_version, oauth_consumer_key, resource_link_id } = body;
    
            return lti_message_type === LtiProvider.MESSAGE_TYPE && lti_version === LtiProvider.VERSION && !!oauth_consumer_key && !!resource_link_id;
        }
    }

    return { LtiProvider };
})();
