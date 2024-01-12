'use strict'

const express = require('express')
const bodyParser = require('body-parser').urlencoded({ extended: false })
const debug = require('../../debug').accounts

const restrictToTopDomain = require('../../handlers/restrict-to-top-domain')

const CreateAccountRequest = require('../../requests/create-account-request')
const AddCertificateRequest = require('../../requests/add-cert-request')
const DeleteAccountRequest = require('../../requests/delete-account-request')
const DeleteAccountConfirmRequest = require('../../requests/delete-account-confirm-request')
const {randomUUID} = require("crypto")
const {ConnectionEventTypes, DidExchangeState, CredentialEventTypes, CredentialState} = require("@aries-framework/core")

/**
 * Returns an Express middleware handler for checking if a particular account
 * exists (used by Signup apps).
 *
 * @param accountManager {AccountManager}
 *
 * @return {Function}
 */
function checkAccountExists (accountManager) {
  return (req, res, next) => {
    const accountUri = req.hostname

    accountManager.accountUriExists(accountUri)
      .then(found => {
        if (!found) {
          debug(`Account ${accountUri} is available (for ${req.originalUrl})`)
          return res.sendStatus(404)
        }
        debug(`Account ${accountUri} is not available (for ${req.originalUrl})`)
        next()
      })
      .catch(next)
  }
}

/**
 * Returns an Express middleware handler for adding a new certificate to an
 * existing account (POST to /api/accounts/cert).
 *
 * @param accountManager
 *
 * @return {Function}
 */
function newCertificate (accountManager) {
  return (req, res, next) => {
    return AddCertificateRequest.handle(req, res, accountManager)
      .catch(err => {
        err.status = err.status || 400
        next(err)
      })
  }
}

/**
 * Returns an Express router for providing user account related middleware
 * handlers.
 *
 * @param accountManager {AccountManager}
 *
 * @return {Router}
 */
function middleware (accountManager) {
  const router = express.Router('/')

  router.get('/', checkAccountExists(accountManager))

  router.post('/api/accounts/new', restrictToTopDomain, bodyParser, CreateAccountRequest.post)
  router.get(['/register', '/api/accounts/new'], restrictToTopDomain, CreateAccountRequest.get)

    router.post('/api/accounts/ssi-new', bodyParser, (req, res) => {
      const agent = req.app.get("agent_ssi")
        agent.events.on(ConnectionEventTypes.ConnectionStateChanged, async ({payload}) => {
          if (payload.connectionRecord.outOfBandId !== req.body.oob_id) return
          if (payload.connectionRecord.state === DidExchangeState.Completed) {
            console.log(`Connection for out-of-band id ${req.body.oob_id} completed`)
            agent.basicMessages.sendMessage(payload.connectionRecord.id, "Grazie per la connessione.")


            // Needed only if we have to create a new schema

            const schemaTemplate = {
              name: 'webid_schema_new' + randomUUID(),
              version: '1.0.0',
              attrNames: ['webid'],
              issuerId: 'did:indy:bcovrin:test:S9BtNBg9dLGv2T26iTBWtZ'
            }
            const {schemaState} = await agent.modules.anoncreds.registerSchema({
              schema: schemaTemplate,
              options: {
                endorserMode: 'internal',
                endorserDid: 'did:indy:bcovrin:test:S9BtNBg9dLGv2T26iTBWtZ'
              },
            })

            if (schemaState.state !== 'finished') {
              throw new Error(
                  `Error registering schema: ${schemaState.state === 'failed' ? schemaState.reason : 'Not Finished'}`
              )
            }

            const credentialDefinitionResult = await agent.modules.anoncreds.registerCredentialDefinition({
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

            const credentialOffer = {
              protocolVersion: 'v2',
              connectionId: payload.connectionRecord.id,
              credentialFormats: {
                anoncreds: {
                  credentialDefinitionId: credentialDefinitionResult.credentialDefinitionState.credentialDefinitionId,
                  //credentialDefinitionId: "did:indy:bcovrin:test:S9BtNBg9dLGv2T26iTBWtZ/anoncreds/v0/CLAIM_DEF/258982/default",
                  attributes: [
                    {mimeType: 'text/plain', name: 'webid', value: req.body.username}
                  ],
                },
              },
            }

            const result = await agent.credentials.offerCredential(credentialOffer)


            agent.events.on(CredentialEventTypes.CredentialStateChanged, async ({payload}) => {
              console.log(payload.credentialRecord.id)
              if (payload.credentialRecord.id !== result.id) return
              if (payload.credentialRecord.state === CredentialState.Done) {
                await CreateAccountRequest.post_ssi(req, res)
              }
            })
          }
        })
    })
  router.post('/api/accounts/cert', restrictToTopDomain, bodyParser, newCertificate(accountManager))

  router.get('/account/delete', restrictToTopDomain, DeleteAccountRequest.get)
  router.post('/account/delete', restrictToTopDomain, bodyParser, DeleteAccountRequest.post)

  router.get('/account/delete/confirm', restrictToTopDomain, DeleteAccountConfirmRequest.get)
  router.post('/account/delete/confirm', restrictToTopDomain, bodyParser, DeleteAccountConfirmRequest.post)

  return router
}

module.exports = {
  middleware,
  checkAccountExists,
  newCertificate
}
