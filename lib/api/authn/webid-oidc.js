'use strict'
/**
 * OIDC Relying Party API handler module.
 */

const express = require('express')
const {routeResolvedFile} = require('../../utils')
const bodyParser = require('body-parser').urlencoded({extended: false})
const OidcManager = require('../../models/oidc-manager')
const {LoginRequest} = require('../../requests/login-request')
const {SharingRequest} = require('../../requests/sharing-request')

const restrictToTopDomain = require('../../handlers/restrict-to-top-domain')

const PasswordResetEmailRequest = require('../../requests/password-reset-email-request')
const PasswordChangeRequest = require('../../requests/password-change-request')
const {
    ConnectionEventTypes,
    DidExchangeState,
    KeyType,
    TypedArrayEncoder,
    ProofEventTypes,
    ProofState
} = require("@aries-framework/core");
const {sleep} = require("@aries-framework/core/build/utils/sleep");


const {AuthCallbackRequest} = require('@solid/oidc-auth-manager').handlers

/**
 * Sets up OIDC authentication for the given app.
 *
 * @param app {Object} Express.js app instance
 * @param argv {Object} Config options hashmap
 */
function initialize(app, argv) {
    const oidc = OidcManager.fromServerConfig(argv)
    app.locals.oidc = oidc
    oidc.initialize()
    // Attach the OIDC API
    app.use('/', middleware(oidc))

    // Perform the actual authentication
    app.use('/', async (req, res, next) => {
        oidc.rs.authenticate({tokenTypesSupported: argv.tokenTypesSupported})(req, res, (err) => {
            // Error handling should be deferred to the ldp in case a user with a bad token is trying
            // to access a public resource
            if (err) {
                req.authError = err
                res.status(200)
            }
            next()
        })
    })

    // Expose session.userId
    app.use('/', (req, res, next) => {
        oidc.webIdFromClaims(req.claims)
            .then(webId => {
                if (webId) {
                    req.session.userId = webId
                }

                next()
            })
            .catch(err => {
                const error = new Error('Could not verify Web ID from token claims')
                error.statusCode = 401
                error.statusText = 'Invalid login'
                error.cause = err
                console.error(err)

                next(error)
            })
    })
}

/**
 * Returns a router with OIDC Relying Party and Identity Provider middleware:
 *
 * @method middleware
 *
 * @param oidc {OidcManager}
 *
 * @return {Router} Express router
 */
function middleware(oidc) {
    const router = express.Router('/')
    // User-facing Authentication API
    router.get(['/login', '/signin'], LoginRequest.get)

    router.post('/login/password', bodyParser, LoginRequest.loginPassword)

    router.post('/login/tls', bodyParser, LoginRequest.loginTls)

    router.post('/login/ssi', bodyParser, LoginRequest.loginSSI)

    router.post('/ajax-endpoint', bodyParser, async (req, res) => {
            // Esegui le operazioni necessarie per la richiesta AJAX
            const agent_vero = req.app.get('agent_ssi')
            const outOfBandRecord_ID = req.body.id_con
            console.log("Il REC_id: " + outOfBandRecord_ID)

            await agent_vero.events.on(ConnectionEventTypes.ConnectionStateChanged, async ({payload}) => {

                if (payload.connectionRecord.outOfBandId !== outOfBandRecord_ID) return
                // if (payload.connectionRecord.state === "response-sent"){
                //     sleep(5000)
                // }
                if (payload.connectionRecord.state === DidExchangeState.Completed) {
                    console.log(`Connection for out-of-band id ${outOfBandRecord_ID} completed`)
                    await agent_vero.basicMessages.sendMessage(payload.connectionRecord.id, "Grazie per la connessione.")
                    await new Promise((resolve) => setTimeout(resolve, 2000))

                    const did = "did:indy:bcovrin:test:S9BtNBg9dLGv2T26iTBWtZ"
                    await agent_vero.dids.import({
                        did,
                        overwrite: true,
                        privateKeys: [
                            {
                                keyType: KeyType.Ed25519,
                                privateKey: TypedArrayEncoder.fromString('solidserver000000000000000000000'),
                            },
                        ],
                    })

                    /*const schemaTemplate = {
                      name: 'webid_schema_new' + randomUUID(),
                      version: '1.0.0',
                      attrNames: ['webid'],
                      issuerId: 'did:indy:bcovrin:test:S9BtNBg9dLGv2T26iTBWtZ'
                    }
                    const { schemaState } = await agent_vero.modules.anoncreds.registerSchema({
                      schema: schemaTemplate,
                      options: {
                        endorserMode: 'internal',
                        endorserDid: 'did:indy:bcovrin:test:S9BtNBg9dLGv2T26iTBWtZ'
                      },
                    })

                    console.log(schemaState)

                    if (schemaState.state !== 'finished') {
                      throw new Error(
                        `Error registering schema: ${schemaState.state === 'failed' ? schemaState.reason : 'Not Finished'}`
                      )
                    }

                    const credentialDefinitionResult = await agent_vero.modules.anoncreds.registerCredentialDefinition({
                      credentialDefinition: {
                        tag: 'default',
                        issuerId: 'did:indy:bcovrin:test:S9BtNBg9dLGv2T26iTBWtZ',
                        schemaId: schemaState.schemaId,
                      },
                      options: {},
                    })

                    if (credentialDefinitionResult.credentialDefinitionState.state === 'failed') {
                      throw new Error(
                        `Error creating credential definition: ${credentialDefinitionResult.credentialDefinitionState.reason}`
                      )
                    }

                    console.log(credentialDefinitionResult)


                    const credentialOffer = {
                      protocolVersion: 'v2',
                      connectionId: payload.connectionRecord.id,
                      credentialFormats: {
                        anoncreds: {
                          credentialDefinitionId: credentialDefinitionResult.credentialDefinitionState.credentialDefinitionId,
                          attributes: [
                            { name: 'webid', value: 'pluto' }
                          ],
                        },
                      },
                    }

                    await agent_vero.credentials.offerCredential(credentialOffer)*/

                    const response = await agent_vero.proofs.requestProof({
                        protocolVersion: 'v2',
                        connectionId: payload.connectionRecord.id,
                        proofFormats: {
                            anoncreds: {
                                name: 'proof-request',
                                version: '1.0',
                                requested_attributes: {
                                    name: {
                                        name: 'webid',
                                        restrictions: [
                                            {
                                                cred_def_id: "did:indy:bcovrin:test:S9BtNBg9dLGv2T26iTBWtZ/anoncreds/v0/CLAIM_DEF/258816/default",
                                            },
                                        ],
                                    },
                                },
                            },
                        },
                    })


                    await agent_vero.events.on(ProofEventTypes.ProofStateChanged, async ({payload}) => {
                        let allowAccess = false
                        if (payload.proofRecord.state === ProofState.Done) {
                            console.log(payload)
                            allowAccess = true
                            const message = allowAccess ? 'Entraaa' : 'Non puoi entrare';

                            res.status(200).json({
                                status: allowAccess,
                                message: message,
                                redirect: '/'
                            });

                        }

                    })


                }
            })

        }
    )
    ;


    router.get('/sharing', SharingRequest.get)
    router.post('/sharing', bodyParser, SharingRequest.share)

    router.get('/account/password/reset', restrictToTopDomain, PasswordResetEmailRequest.get)
    router.post('/account/password/reset', restrictToTopDomain, bodyParser, PasswordResetEmailRequest.post)

    router.get('/account/password/change', restrictToTopDomain, PasswordChangeRequest.get)
    router.post('/account/password/change', restrictToTopDomain, bodyParser, PasswordChangeRequest.post)

    router.get('/.well-known/solid/logout/', (req, res) => res.redirect('/logout'))

    router.get('/goodbye', (req, res) => {
        res.render('auth/goodbye')
    })

    // The relying party callback is called at the end of the OIDC signin process
    router.get('/api/oidc/rp/:issuer_id', AuthCallbackRequest.get)

    // Static assets related to authentication
    const authAssets = [
        ['/.well-known/solid/login/', '../static/popup-redirect.html', false],
        ['/common/', 'solid-auth-client/dist-popup/popup.html']
    ]
    authAssets.map(args => routeResolvedFile(router, ...args))

    // Initialize the OIDC Identity Provider routes/api
    // router.get('/.well-known/openid-configuration', discover.bind(provider))
    // router.get('/jwks', jwks.bind(provider))
    // router.post('/register', register.bind(provider))
    // router.get('/authorize', authorize.bind(provider))
    // router.post('/authorize', authorize.bind(provider))
    // router.post('/token', token.bind(provider))
    // router.get('/userinfo', userinfo.bind(provider))
    // router.get('/logout', logout.bind(provider))
    const oidcProviderApi = require('oidc-op-express')(oidc.provider)
    router.use('/', oidcProviderApi)

    return router
}

/**
 * Sets the `WWW-Authenticate` response header for 401 error responses.
 * Used by error-pages handler.
 *
 * @param req {IncomingRequest}
 * @param res {ServerResponse}
 * @param err {Error}
 */
function setAuthenticateHeader(req, res, err) {
    const locals = req.app.locals

    const errorParams = {
        realm: locals.host.serverUri,
        scope: 'openid webid',
        error: err.error,
        error_description: err.error_description,
        error_uri: err.error_uri
    }

    const challengeParams = Object.keys(errorParams)
        .filter(key => !!errorParams[key])
        .map(key => `${key}="${errorParams[key]}"`)
        .join(', ')

    res.set('WWW-Authenticate', 'Bearer ' + challengeParams)
}

/**
 * Provides custom logic for error status code overrides.
 *
 * @param statusCode {number}
 * @param req {IncomingRequest}
 *
 * @returns {number}
 */
function statusCodeOverride(statusCode, req) {
    if (isEmptyToken(req)) {
        return 400
    } else {
        return statusCode
    }
}

/**
 * Tests whether the `Authorization:` header includes an empty or missing Bearer
 * token.
 *
 * @param req {IncomingRequest}
 *
 * @returns {boolean}
 */
function isEmptyToken(req) {
    const header = req.get('Authorization')

    if (!header) {
        return false
    }

    if (header.startsWith('Bearer')) {
        const fragments = header.split(' ')

        if (fragments.length === 1) {
            return true
        } else if (!fragments[1]) {
            return true
        }
    }

    return false
}

module.exports = {
    initialize,
    isEmptyToken,
    middleware,
    setAuthenticateHeader,
    statusCodeOverride
}
