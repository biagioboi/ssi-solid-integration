'use strict'
/* eslint-disable no-mixed-operators */

const debug = require('./../debug').authentication
const QRCode = require('qrcode')


const AuthRequest = require('./auth-request')
const { PasswordAuthenticator, TlsAuthenticator, SSIAuthenticator } = require('../models/authenticator')

const {
  ConnectionEventTypes,
  CredentialEventTypes,
  CredentialState,
  DidExchangeState, KeyType, TypedArrayEncoder, ProofEventTypes, ProofState,
} = require('@aries-framework/core')

const {
  IndyVdrRegisterSchemaOptions,
} = require('@aries-framework/indy-vdr')
const {randomUUID} = require("crypto");


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
        invitationUrl: outOfBandRecord.outOfBandInvitation.toUrl({ domain: 'https://5a79-193-205-162-72.ngrok-free.app' }),
        outOfBandRecord,
      }
    }
    const run_fun = async () => {
      console.log('Initializing the issuer...')
      const agent_vero = req.app.get('agent_ssi');
      console.log('Initializing the credential listener...')
      const { outOfBandRecord, invitationUrl } = await create_invitation(agent_vero)

      console.log(invitationUrl)
      let qrcode_png
      let oobRecord
      console.log("oobRecord")
      await QRCode.toDataURL(invitationUrl, { version: 22 }).then(qrcode_generated => {
        qrcode_png = qrcode_generated
        oobRecord = outOfBandRecord.id
      });
      console.log('Listening for connection changes...')
      return {qrcode_png, oobRecord}
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
    let qrcode_to_return
    let oobRecord

    await this.getQrCodeSSI(req).then(qrcode_generated => {
      qrcode_to_return = qrcode_generated.qrcode_png
      oobRecord = qrcode_generated.oobRecord
    });
    const queryString = req && req.url && req.url.replace(/[^?]+\?/, '') || ''
    const params = Object.assign({}, this.authQueryParams,
      {
        registerUrl: this.registerUrl(),
        returnToUrl: this.returnToUrl,
        enablePassword: this.localAuth.password,
        enableTls: this.localAuth.tls,
        tlsUrl: `/login/tls?${encodeURIComponent(queryString)}`,
        qrcode: qrcode_to_return,
        oobRecord: oobRecord
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

