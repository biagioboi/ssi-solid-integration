'use strict'
/* eslint-disable no-mixed-operators */

const debug = require('./../debug').authentication
const QRCode = require('qrcode')

const AuthRequest = require('./auth-request')
const { PasswordAuthenticator, TlsAuthenticator, SSIAuthenticator } = require('../models/authenticator')

const {
  Agent, InitConfig,
  ConnectionEventTypes,
  ConnectionStateChangedEvent,
  WsOutboundTransport,
  HttpOutboundTransport,
  AutoAcceptCredential,
  CredentialEventTypes,
  CredentialState,
  CredentialStateChangedEvent,
  DidExchangeState,
  OutOfBandRecord
} = require('@aries-framework/core')

const { AskarModule } = require('@aries-framework/askar')
//const { ariesAskar } = require('@hyperledger/aries-askar-nodejs')

//const {AnonCredsModule} = require('@aries-framework/anoncreds');
const { IndySdkModule } = require('@aries-framework/indy-sdk')
const indySdk = require('indy-sdk')
const { agentDependencies, HttpInboundTransport } = require('@aries-framework/node')
const { Schema } = require('indy-sdk')
const fetch = require('node-fetch')

const PASSWORD_AUTH = 'password'
const TLS_AUTH = 'tls'
const SSI = 'ssi'

/**
 * Models a local Login request
 */
class LoginRequest extends AuthRequest {
  /**
   * @constructor
   * @param options {Object}
   *
   * @param [options.response] {ServerResponse} middleware `res` object
   * @param [options.session] {Session} req.session
   * @param [options.userStore] {UserStore}
   * @param [options.accountManager] {AccountManager}
   * @param [options.returnToUrl] {string}
   * @param [options.authQueryParams] {Object} Key/value hashmap of parsed query
   *   parameters that will be passed through to the /authorize endpoint.
   * @param [options.authenticator] {Authenticator} Auth strategy by which to
   *   log in
   */
  constructor (options) {
    super(options)

    this.authenticator = options.authenticator
    this.authMethod = options.authMethod
  }

  /**
   * Factory method, returns an initialized instance of LoginRequest
   * from an incoming http request.
   *
   * @param req {IncomingRequest}
   * @param res {ServerResponse}
   * @param authMethod {string}
   *
   * @return {LoginRequest}
   */
  static fromParams (req, res, authMethod) {
    const options = AuthRequest.requestOptions(req, res)
    options.authMethod = authMethod

    switch (authMethod) {
      case PASSWORD_AUTH:
        options.authenticator = PasswordAuthenticator.fromParams(req, options)
        break

      case TLS_AUTH:
        options.authenticator = TlsAuthenticator.fromParams(req, options)
        break

      case SSI:
        options.authenticator = SSIAuthenticator.fromParams(req, options)
        break

      default:
        options.authenticator = null
        break
    }

    return new LoginRequest(options)
  }

  /**
   * Handles a Login GET request on behalf of a middleware handler, displays
   * the Login page.
   * Usage:
   *
   *   ```
   *   app.get('/login', LoginRequest.get)
   *   ```
   *
   * @param req {IncomingRequest}
   * @param res {ServerResponse}
   */
  static get (req, res) {
    const request = LoginRequest.fromParams(req, res)

    request.renderForm(null, req)
  }

  /**
   * Handles a Login via Username+Password.
   * Errors encountered are displayed on the Login form.
   * Usage:
   *
   *   ```
   *   app.post('/login/password', LoginRequest.loginPassword)
   *   ```
   *
   * @param req
   * @param res
   *
   * @return {Promise}
   */
  static loginPassword (req, res) {
    debug('Logging in via username + password')

    const request = LoginRequest.fromParams(req, res, PASSWORD_AUTH)

    return LoginRequest.login(request)
  }

  /**
   * Handles a Login via WebID-TLS.
   * Errors encountered are displayed on the Login form.
   * Usage:
   *
   *   ```
   *   app.post('/login/tls', LoginRequest.loginTls)
   *   ```
   *
   * @param req
   * @param res
   *
   * @return {Promise}
   */
  static loginTls (req, res) {
    debug('Logging in via WebID-TLS certificate')

    const request = LoginRequest.fromParams(req, res, TLS_AUTH)

    /* Function for retrival of user and recall to the method used in the specific implementation */
    return LoginRequest.login(request)
  }

  /**
   * Handles a Login via SSI.
   * Errors encountered are displayed on the Login form.
   * Usage:
   *
   *   ```
   *   app.post('/login/ssi', LoginRequest.loginSSI)
   *   ```
   *
   * @param req
   * @param res
   *
   * @return {Promise}
   */

  static loginSSI (req, res) {
    debug('Logging in via SSI')
    const getGenesisTransaction = async (url) => {
      const response = await fetch(url)
      return await response.text()
    }
    const inizialize_agent = async () => {
      const config = {
        label: 'docs-nodejs-agent',

        walletConfig: {
          id: 'wallet-id',
          key: 'testkey0000000000000000000000000',
        },
        autoAcceptConnections: true,
        endpoints: ['http://172.19.148.62:3000'],
      }

      const agent = new Agent({
        config,
        dependencies: agentDependencies,
      })
      // Registering the required in- and outbound transports
      agent.registerOutboundTransport(new HttpOutboundTransport())
      agent.registerOutboundTransport(new WsOutboundTransport())
      agent.registerInboundTransport(new HttpInboundTransport({ port: 3000 }))
      await agent.initialize()
      return agent
    }


    const create_invitation = async (agent_vero) => {
      const outOfBandRecord = await agent_vero.oob.createInvitation()
      return {
        invitationUrl: outOfBandRecord.outOfBandInvitation.toUrl({ domain: 'http://172.19.148.62:3000' }),
        outOfBandRecord,
      }
    }
    const receiveInvitation = async (agent_vero, invitationUrl) => {
      const { outOfBandRecord } = await agent_vero.oob.receiveInvitationFromUrl(invitationUrl)

      return outOfBandRecord
    }
    const initializeHolderAgent = async () => {
      const genesisTransactionsBCovrinTestNet = await getGenesisTransaction('http://test.bcovrin.vonx.io/genesis')

      // Simple agent configuration. This sets some basic fields like the wallet
      // configuration and the label. It also sets the mediator invitation url,
      // because this is most likely required in a mobile environment.
      const config = {
        label: 'demo-agent-holder',
        walletConfig: {
          id: 'demo-agent-holder',
          key: 'testkey0000000000000000000000000',
        },
        indyLedgers: [
          {
            id: 'bcovrin-test-net',
            isProduction: false,
            indyNamespace: 'bcovrin:test',
            genesisTransactions: genesisTransactionsBCovrinTestNet,
          },
        ],
        autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
        autoAcceptConnections: true,
        endpoints: ['http://172.19.148.62:3002'],
      }

      // A new instance of an agent is created here
      const agent = new Agent({ config, dependencies: agentDependencies })

      // Register a simple `WebSocket` outbound transport
      agent.registerOutboundTransport(new WsOutboundTransport())

      // Register a simple `Http` outbound transport
      agent.registerOutboundTransport(new HttpOutboundTransport())

      // Register a simple `Http` inbound transport
      agent.registerInboundTransport(new HttpInboundTransport({ port: 3002 }))

      // Initialize the agent
      await agent.initialize()

      return agent
    }

    const initializeIssuerAgent = async () => {
      const genesisTransactionsBCovrinTestNet = await getGenesisTransaction('http://test.bcovrin.vonx.io/genesis')
      // Simple agent configuration. This sets some basic fields like the wallet
      // configuration and the label.
      const config = {
        label: 'demo-agent-issuer',
        walletConfig: {
          id: 'demo-agent-issuer',
          key: 'testkey0000000000000000000000000',
        },
        publicDidSeed: 'demoissuerdidseed000000000000000',
        indyLedgers: [
          {
            id: 'bcovrin-test-net',
            isProduction: false,
            indyNamespace: 'bcovrin:test',
            genesisTransactions: genesisTransactionsBCovrinTestNet,
          },
        ],
        autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
        autoAcceptConnections: true,
        endpoints: ['http://localhost:3000']
      }

      // A new instance of an agent is created here
      const agent = new Agent({
        config, dependencies: agentDependencies, modules: {
          indySdk: new IndySdkModule({
            indySdk
          })
        }
      })

      // Register a simple `WebSocket` outbound transport
      agent.registerOutboundTransport(new WsOutboundTransport())

      // Register a simple `Http` outbound transport
      agent.registerOutboundTransport(new HttpOutboundTransport())

      // Register a simple `Http` inbound transport
      agent.registerInboundTransport(new HttpInboundTransport({ port: 3000 }))

      // Initialize the agent
      await agent.initialize()

      return agent
    }

    const registerSchema = async (agent) => {
      let x = agent.ledger.registerSchema({
        attributes: ['webid'],
        name: 'solid_auth_schema',
        version: '4.0'
      })
      console.log(x)
      return x
    }

    const registerCredentialDefinition = async (agent, schema) => {
      //console.log(schema);
      //return schema;

      try {
        let z = agent.ledger.registerCredentialDefinition({
          schema,
          supportRevocation: false,
          tag: 'default'
        }).catch((errore) => schema)
        return z
      } catch (error) {
        console.log(error)
      }
    }

    const setupCredentialListener = (holder) => {
      holder.events.on(
        CredentialEventTypes.CredentialStateChanged,
        async ({ payload }) => {
          switch (payload.credentialRecord.state) {
            case CredentialState.OfferReceived:
              console.log('received a credential')
              // custom logic here
              await holder.credentials.acceptOffer({
                credentialRecordId: payload.credentialRecord.id
              })
            case CredentialState.Done:
              console.log(`Credential for credential id ${payload.credentialRecord.id} is accepted`)
              // For demo purposes we exit the program here.
              process.exit(0)
          }
        }
      )
    }

    const setupConnectionListener = (agent, outOfBandRecord, cb) => {
      agent.events.on(ConnectionEventTypes.ConnectionStateChanged, async ({ payload }) => {
        console.log(payload)
        console.log(outOfBandRecord)
        if (payload.connectionRecord.outOfBandId !== outOfBandRecord.id) return
        if (payload.connectionRecord.state === 'completed') {
          // the connection is now ready for usage in other protocols!
//          console.log('Connection for out-of-band id ' + outOfBandRecord.id +  'completed')
          console.log(`Connection for out-of-band id ${outOfBandRecord.id} completed`)
          // Custom business logic can be included here
          // In this example we can send a basic message to the connection, but
          // anything is possible
          await cb(payload.connectionRecord.id)

          // We exit the flow
        }
      })
    }

    const issueCredential = async (agent, credentialDefinitionId, connectionId) => {
      console.log(credentialDefinitionId)
      const credentialOffer = {
        protocolVersion: 'v1',
        connectionId,
        credentialFormats: {
          indy: {
            credentialDefinitionId,
            attributes: [
              { name: 'webid', value: 'pluto' }
            ],
          },
        },
      }

      const offerResult = await agent.credentials.offerCredential(credentialOffer)
      return offerResult
    }

    const flow = (agent) => async (connectionId) => {
      console.log('Registering the schema...')
      const schema = await registerSchema(agent)
      console.log(schema)
      console.log('Registering the credential definition...')
      const credentialDefinition = await registerCredentialDefinition(agent, schema)
      console.log('Issuing the credential...')
      await issueCredential(agent, credentialDefinition.id, connectionId)
    }

    const fs = require('fs')

    run_fun()

  }

  getQrCodeSSI(req) {
    const create_invitation = async (agent_vero) => {
      const outOfBandRecord = await agent_vero.oob.createInvitation()
      return {
        invitationUrl: outOfBandRecord.outOfBandInvitation.toUrl({ domain: 'http://172.19.32.136:3000' }),
        outOfBandRecord,
      }
    }
    const run_fun = async () => {
      console.log('Initializing the issuer...')
      const agent_vero = req.app.get('agent_ssi');
      console.log('Initializing the credential listener...')
      const { outOfBandRecord, invitationUrl } = await create_invitation(agent_vero)
      console.log(invitationUrl)
      let qrcode_png;
      await QRCode.toDataURL(invitationUrl, { version: 22 }).then(qrcode_generated => {
        qrcode_png = qrcode_generated
      });
      console.log('Listening for connection changes...')
      return qrcode_png
    }

    return run_fun();
  }

  /**
   * Performs the login operation -- loads and validates the
   * appropriate user, inits the session with credentials, and redirects the
   * user to continue their auth flow.
   *
   * @param request {LoginRequest}
   *
   * @return {Promise}
   */

  static login (request) {
    return request.authenticator.findValidUser()

      .then(validUser => {
        request.initUserSession(validUser)

        request.redirectPostLogin(validUser)
      })

      .catch(error => request.error(error))
  }

  /**
   * Returns a URL to redirect the user to after login.
   * Either uses the provided `redirect_uri` auth query param, or simply
   * returns the user profile URI if none was provided.
   *
   * @param validUser {UserAccount}
   *
   * @return {string}
   */
  postLoginUrl (validUser) {
    // Login request is part of an app's auth flow
    if (/token|code/.test(this.authQueryParams.response_type)) {
      return this.sharingUrl()
      // Login request is a user going to /login in browser
    } else if (validUser) {
      return this.authQueryParams.redirect_uri || validUser.accountUri
    }
  }

  /**
   * Redirects the Login request to continue on the OIDC auth workflow.
   */
  redirectPostLogin (validUser) {
    const uri = this.postLoginUrl(validUser)
    debug('Login successful, redirecting to ', uri)
    this.response.redirect(uri)
  }

  /**
   * Renders the login form
   */
  async renderForm (error, req) {
    let qrcode_to_return;
    await this.getQrCodeSSI(req).then(qrcode_generated => {
      qrcode_to_return = qrcode_generated
    });
    const queryString = req && req.url && req.url.replace(/[^?]+\?/, '') || ''
    const params = Object.assign({}, this.authQueryParams,
      {
        registerUrl: this.registerUrl(),
        returnToUrl: this.returnToUrl,
        enablePassword: this.localAuth.password,
        enableTls: this.localAuth.tls,
        tlsUrl: `/login/tls?${encodeURIComponent(queryString)}`,
        qrcode: qrcode_to_return
      })

    if (error) {
      params.error = error.message
      this.response.status(error.statusCode)
    }
    this.response.render('auth/login', params)
  }
}

module.exports = {
  LoginRequest,
  PASSWORD_AUTH,
  TLS_AUTH,
  SSI
}

