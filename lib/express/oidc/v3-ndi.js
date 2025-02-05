// This file implements NDI OIDC for Singpass authentication and Corppass OIDC
// for Corppass authentication.

const express = require('express')
const fs = require('fs')
const { render } = require('mustache')
const jose = require('jose')
const path = require('path')
const { v1: uuid } = require('uuid')
const { faker } = require('@faker-js/faker')

const assertions = require('../../assertions')
const { generateAuthCode, lookUpByAuthCode } = require('../../auth-code')
const {
  buildAssertURL,
  idGenerator,
  customProfileFromHeaders,
} = require('./utils')
const { InvalidClientError } = require('./errors')
const { myinfo } = require('../../assertions')

const LOGIN_TEMPLATE = fs.readFileSync(
  path.resolve(__dirname, '../../../static/html/login-page.html'),
  'utf8',
)

const aspPublic = fs.readFileSync(
  path.resolve(__dirname, '../../../static/certs/oidc-v2-asp-public.json'),
)

const aspSecret = fs.readFileSync(
  path.resolve(__dirname, '../../../static/certs/oidc-v2-asp-secret.json'),
)

const rpPublic = fs.readFileSync(
  path.resolve(__dirname, '../../../static/certs/oidc-v2-rp-public.json'),
)

const singpass_allowed_scopes = [
  'openid',
  'uinfin',
  'partialuinfin',
  'name',
  'aliasname',
  'hanyupinyinname',
  'hanyupinyinaliasname',
  'marriedname',
  'sex',
  'race',
  'secondaryrace',
  'dialect',
  'dob',
  'residentialstatus',
  'nationality',
  'birthcountry',
  'passportnumber',
  'passportexpirydate',
  'passtype',
  'passstatus',
  'passexpirydate',
  'employmentsector',
  'mobileno',
  'email',
  'regadd',
  'hdbtype',
  'housingtype',
  'cpfbalances.oa',
  'cpfbalances.ma',
  'cpfbalances.ra',
  'cpfbalances.sa',
  'cpfcontributions',
  'cpfhousingwithdrawal',
  'cpfinvestmentscheme.account',
  'cpfinvestmentscheme.sdsnetshareholdingqty',
  'cpfinvestmentscheme.saqparticipationstatus',
  'noa-basic',
  'noahistory-basic',
  'noa',
  'noahistory',
  'ownerprivate',
  'drivinglicence.comstatus',
  'drivinglicence.totaldemeritpoints',
  'drivinglicence.suspension.startdate',
  'drivinglicence.suspension.enddate',
  'drivinglicence.disqualification.startdate',
  'drivinglicence.disqualification.enddate',
  'drivinglicence.revocation.startdate',
  'drivinglicence.revocation.enddate',
  'drivinglicence.pdl.validity',
  'drivinglicence.pdl.expirydate',
  'drivinglicence.pdl.classes',
  'drivinglicence.qdl.validity',
  'drivinglicence.qdl.expirydate',
  'drivinglicence.qdl.classes',
  'drivinglicence.photocardserialno',
  'vehicles.vehicleno',
  'vehicles.type',
  'vehicles.iulabelno',
  'vehicles.make',
  'vehicles.model',
  'vehicles.chassisno',
  'vehicles.engineno',
  'vehicles.motorno',
  'vehicles.yearofmanufacture',
  'vehicles.firstregistrationdate',
  'vehicles.originalregistrationdate',
  'vehicles.coecategory',
  'vehicles.coeexpirydate',
  'vehicles.roadtaxexpirydate',
  'vehicles.quotapremium',
  'vehicles.openmarketvalue',
  'vehicles.co2emission',
  'vehicles.status',
  'vehicles.primarycolour',
  'vehicles.secondarycolour',
  'vehicles.attachment1',
  'vehicles.attachment2',
  'vehicles.attachment3',
  'vehicles.scheme',
  'vehicles.thcemission',
  'vehicles.coemission',
  'vehicles.noxemission',
  'vehicles.pmemission',
  'vehicles.enginecapacity',
  'vehicles.powerrate',
  'vehicles.effectiveownership',
  'vehicles.propellant',
  'vehicles.maximumunladenweight',
  'vehicles.maximumladenweight',
  'vehicles.minimumparfbenefit',
  'vehicles.nooftransfers',
  'vehicles.vpc',
  'marital',
  'marriagedate',
  'divorcedate',
  'marriagecertno',
  'countryofmarriage',
  'childrenbirthrecords.birthcertno',
  'childrenbirthrecords.name',
  'childrenbirthrecords.aliasname',
  'childrenbirthrecords.hanyupinyinname',
  'childrenbirthrecords.hanyupinyinaliasname',
  'childrenbirthrecords.marriedname',
  'childrenbirthrecords.sex',
  'childrenbirthrecords.race',
  'childrenbirthrecords.secondaryrace',
  'childrenbirthrecords.dob',
  'childrenbirthrecords.tob',
  'childrenbirthrecords.dialect',
  'childrenbirthrecords.lifestatus',
  'childrenbirthrecords.vaccinationrequirements',
  'childrenbirthrecords.sgcitizenatbirthind',
  'sponsoredchildrenrecords.nric',
  'sponsoredchildrenrecords.name',
  'sponsoredchildrenrecords.aliasname',
  'sponsoredchildrenrecords.hanyupinyinname',
  'sponsoredchildrenrecords.hanyupinyinaliasname',
  'sponsoredchildrenrecords.marriedname',
  'sponsoredchildrenrecords.sex',
  'sponsoredchildrenrecords.race',
  'sponsoredchildrenrecords.secondaryrace',
  'sponsoredchildrenrecords.dialect',
  'sponsoredchildrenrecords.dob',
  'sponsoredchildrenrecords.birthcountry',
  'sponsoredchildrenrecords.lifestatus',
  'sponsoredchildrenrecords.residentialstatus',
  'sponsoredchildrenrecords.nationality',
  'sponsoredchildrenrecords.scprgrantdate',
  'sponsoredchildrenrecords.vaccinationrequirements',
  'employment',
  'occupation',
  'cpfemployers',
  'academicqualifications.transcripts',
  'academicqualifications.certificates',
  'ltavocationallicences.tdvl.licencename',
  'ltavocationallicences.tdvl.vocationallicencenumber',
  'ltavocationallicences.tdvl.expirydate',
  'ltavocationallicences.tdvl.status',
  'ltavocationallicences.pdvl.licencename',
  'ltavocationallicences.pdvl.vocationallicencenumber',
  'ltavocationallicences.pdvl.expirydate',
  'ltavocationallicences.pdvl.status',
  'ltavocationallicences.bavl.licencename',
  'ltavocationallicences.bavl.vocationallicencenumber',
  'ltavocationallicences.bavl.expirydate',
  'ltavocationallicences.bavl.status',
  'ltavocationallicences.bdvl.licencename',
  'ltavocationallicences.bdvl.vocationallicencenumber',
  'ltavocationallicences.bdvl.expirydate',
  'ltavocationallicences.bdvl.status',
  'ltavocationallicences.odvl.licencename',
  'ltavocationallicences.odvl.vocationallicencenumber',
  'ltavocationallicences.odvl.expirydate',
  'ltavocationallicences.odvl.status',
  'hdbownership.noofowners',
  'hdbownership.address',
  'hdbownership.hdbtype',
  'hdbownership.leasecommencementdate',
  'hdbownership.termoflease',
  'hdbownership.dateofpurchase',
  'hdbownership.dateofownershiptransfer',
  'hdbownership.loangranted',
  'hdbownership.originalloanrepayment',
  'hdbownership.balanceloanrepayment',
  'hdbownership.outstandingloanbalance',
  'hdbownership.monthlyloaninstalment',
  'hdbownership.purchaseprice',
  'hdbownership.outstandinginstalment',
  'pioneergen.eligibility',
  'merdekagen.eligibility',
]

const singpass_token_endpoint_auth_signing_alg_values_supported = [
  'ES256',
  'ES384',
  'ES512',
]

const token_endpoint_auth_signing_alg_values_supported = {
  singPass: singpass_token_endpoint_auth_signing_alg_values_supported,
}

const singpass_id_token_encryption_alg_values_supported = [
  'ECDH-ES+A256KW',
  'ECDH-ES+A192KW',
  'ECDH-ES+A128KW',
]

const id_token_encryption_alg_values_supported = {
  singPass: singpass_id_token_encryption_alg_values_supported,
}

function findEcdhEsEncryptionKey(jwks, crv, algs) {
  let encryptionKey = jwks.keys.find(
    (item) =>
      item.use === 'enc' &&
      item.kty === 'EC' &&
      item.crv === crv &&
      (!item.alg ||
        (item.alg === 'ECDH-ES+A256KW' &&
          algs.some((alg) => alg === item.alg))),
  )
  if (encryptionKey) {
    return {
      ...encryptionKey,
      ...(!encryptionKey.alg ? { alg: 'ECDH-ES+A256KW' } : {}),
    }
  }
  encryptionKey = jwks.keys.find(
    (item) =>
      item.use === 'enc' &&
      item.kty === 'EC' &&
      item.crv === crv &&
      (!item.alg ||
        (item.alg === 'ECDH-ES+A192KW' &&
          algs.some((alg) => alg === item.alg))),
  )
  if (encryptionKey) {
    return {
      ...encryptionKey,
      ...(!encryptionKey.alg ? { alg: 'ECDH-ES+A256KW' } : {}),
    }
  }
  encryptionKey = jwks.keys.find(
    (item) =>
      item.use === 'enc' &&
      item.kty === 'EC' &&
      item.crv === crv &&
      (!item.alg ||
        (item.alg === 'ECDH-ES+A128KW' &&
          algs.some((alg) => alg === item.alg))),
  )
  if (encryptionKey) {
    return {
      ...encryptionKey,
      ...(!encryptionKey.alg ? { alg: 'ECDH-ES+A256KW' } : {}),
    }
  }
  return null
}

function findEncryptionKey(jwks, algs) {
  let encryptionKey = findEcdhEsEncryptionKey(jwks, 'P-521', algs)
  if (encryptionKey) {
    return encryptionKey
  }
  if (!encryptionKey) {
    encryptionKey = findEcdhEsEncryptionKey(jwks, 'P-384', algs)
  }
  if (encryptionKey) {
    return encryptionKey
  }
  if (!encryptionKey) {
    encryptionKey = findEcdhEsEncryptionKey(jwks, 'P-256', algs)
  }
  if (encryptionKey) {
    return encryptionKey
  }
  if (!encryptionKey) {
    encryptionKey = jwks.keys.find(
      (item) =>
        item.use === 'enc' &&
        item.kty === 'RSA' &&
        (!item.alg ||
          (item.alg === 'RSA-OAEP-256' &&
            algs.some((alg) => alg === item.alg))),
    )
  }
  if (encryptionKey) {
    return { ...encryptionKey, alg: 'RSA-OAEP-256' }
  }
}

async function getRelayPartyKeySets() {
  const rpJwksEndpoint = process.env.SP_RP_JWKS_ENDPOINT

  let rpKeysetString

  if (rpJwksEndpoint) {
    try {
      const rpKeysetResponse = await fetch(rpJwksEndpoint, {
        method: 'GET',
      })
      rpKeysetString = await rpKeysetResponse.text()
      if (!rpKeysetResponse.ok) {
        throw new Error(rpKeysetString)
      }
    } catch (e) {
      console.error('Failed to fetch RP JWKS from', rpJwksEndpoint, e.message)
      throw InvalidClientError(
        400,
        `Failed to fetch RP JWKS from specified endpoint: ${e.message}`,
      )
    }
  } else {
    // If the endpoint is not defined, default to the sample keyset we provided.
    rpKeysetString = rpPublic
  }

  let keysetJson
  try {
    keysetJson = JSON.parse(rpKeysetString)
  } catch (e) {
    console.error('Unable to parse RP keyset', e.message)
    throw InvalidClientError(400, `Unable to parse RP keyset: ${e.message}`)
  }

  const encryptionKey = findEncryptionKey(
    keysetJson,
    id_token_encryption_alg_values_supported.singPass,
  )

  return { keysetJson, encryptionKey }
}

function config(app, { showLoginPage, isStateless }) {
  const profiles = assertions.oidc.singPass
  const defaultProfile =
    profiles.find((p) => p.nric === process.env.MOCKPASS_NRIC) || profiles[0]

  app.get(`/singpass/v3/auth`, (req, res) => {
    const {
      scope,
      response_type,
      client_id,
      redirect_uri: redirectURI,
      state,
      nonce,
    } = req.query

    const invalidScopes = scope
      .split(' ')
      .filter((s) => !singpass_allowed_scopes.includes(s))
    if (invalidScopes.length !== 0) {
      return res.status(400).send({
        error: 'invalid_scope',
        error_description: `Unknown scope ${invalidScopes.join(' ')}`,
      })
    }
    if (response_type !== 'code') {
      return res.status(400).send({
        error: 'unsupported_response_type',
        error_description: `Unknown response_type ${response_type}`,
      })
    }
    if (!client_id) {
      return res.status(400).send({
        error: 'invalid_request',
        error_description: 'Missing client_id',
      })
    }
    if (!redirectURI) {
      return res.status(400).send({
        error: 'invalid_request',
        error_description: 'Missing redirect_uri',
      })
    }
    if (!nonce) {
      return res.status(400).send({
        error: 'invalid_request',
        error_description: 'Missing nonce',
      })
    }
    if (!state) {
      return res.status(400).send({
        error: 'invalid_request',
        error_description: 'Missing state',
      })
    }

    // Identical to OIDC v1
    if (showLoginPage(req)) {
      const values = profiles
        .filter((profile) => assertions.myinfo.v3.personas[profile.nric])
        .map((profile) => {
          const authCode = generateAuthCode(
            { profile, scopes: scope, nonce },
            { isStateless },
          )
          const assertURL = buildAssertURL(redirectURI, authCode, state)
          const id = idGenerator.singPass(profile)
          return { id, assertURL }
        })

      console.log('setup scopes', scope)
      const response = render(LOGIN_TEMPLATE, {
        values,
        redirectURI,
        state,
        nonce,
        scopes: scope,
      })
      res.send(response)
    } else {
      const profile = customProfileFromHeaders.singPass(req) || defaultProfile
      const authCode = generateAuthCode({ profile, nonce }, { isStateless })
      const assertURL = buildAssertURL(redirectURI, authCode, state)
      console.warn(
        `Redirecting login from ${req.query.client_id} to ${redirectURI}`,
      )
      res.redirect(assertURL)
    }
  })

  app.post(
    '/singpass/v3/auth',
    express.urlencoded({ extended: false }),
    (req, res) => {
      const { nric, state, nonce, redirectURI, scopes } = req.body

      const formattedProfile = { customProfile: true, nric, uuid: uuid() }
      const authCode = generateAuthCode(
        { profile: formattedProfile, scopes, nonce },
        { isStateless },
      )
      const assertURL = buildAssertURL(redirectURI, authCode, state)
      console.warn(
        `Redirecting login from ${req.query.client_id} to ${redirectURI}`,
      )
      res.redirect(assertURL)
    },
  )

  app.post(
    `/singpass/v3/token`,
    express.urlencoded({ extended: false }),
    async (req, res) => {
      const {
        client_id,
        redirect_uri: redirectURI,
        grant_type,
        code: authCode,
        client_assertion_type,
        client_assertion: clientAssertion,
      } = req.body

      // Only SP requires client_id
      if (!client_id) {
        console.error('Missing client_id')
        return res.status(400).send({
          error: 'invalid_request',
          error_description: 'Missing client_id',
        })
      }
      if (!redirectURI) {
        console.error('Missing redirect_uri')
        return res.status(400).send({
          error: 'invalid_request',
          error_description: 'Missing redirect_uri',
        })
      }
      if (grant_type !== 'authorization_code') {
        console.error('Unknown grant_type', grant_type)
        return res.status(400).send({
          error: 'unsupported_grant_type',
          error_description: `Unknown grant_type ${grant_type}`,
        })
      }
      if (!authCode) {
        return res.status(400).send({
          error: 'invalid_request',
          error_description: 'Missing code',
        })
      }
      if (
        client_assertion_type !==
        'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      ) {
        console.error('Unknown client_assertion_type', client_assertion_type)
        return res.status(400).send({
          error: 'invalid_request',
          error_description: `Unknown client_assertion_type ${client_assertion_type}`,
        })
      }
      if (!clientAssertion) {
        console.error('Missing client_assertion')
        return res.status(400).send({
          error: 'invalid_request',
          error_description: 'Missing client_assertion',
        })
      }

      // Step 0: Get the RP keyset
      let rpKeysetJson, rpEncryptionKey

      try {
        const { keysetJson, encryptionKey } = await getRelayPartyKeySets()
        rpKeysetJson = keysetJson
        rpEncryptionKey = encryptionKey
      } catch (e) {
        return res.status(e.code).send({
          error: e.error,
          error_description: e.message,
        })
      }

      console.log(rpKeysetJson)
      const rpKeyset = jose.createLocalJWKSet(rpKeysetJson)
      // Step 0.5: Verify client assertion with RP signing key
      let clientAssertionResult
      try {
        clientAssertionResult = await jose.jwtVerify(clientAssertion, rpKeyset)
      } catch (e) {
        console.error(
          'Unable to verify client_assertion',
          e.message,
          clientAssertion,
        )
        return res.status(401).send({
          error: 'invalid_client',
          error_description: `Unable to verify client_assertion: ${e.message}`,
        })
      }

      const { payload: clientAssertionClaims, protectedHeader } =
        clientAssertionResult
      console.debug(
        'Received client_assertion',
        clientAssertionClaims,
        protectedHeader,
      )
      if (
        !token_endpoint_auth_signing_alg_values_supported.singPass.some(
          (item) => item === protectedHeader.alg,
        )
      ) {
        console.warn(
          'The client_assertion alg',
          protectedHeader.alg,
          'does not meet required token_endpoint_auth_signing_alg_values_supported',
          token_endpoint_auth_signing_alg_values_supported.singPass,
        )
      }

      if (!protectedHeader.typ) {
        console.error('The client_assertion typ should be set')
        return res.status(401).send({
          error: 'invalid_client',
          error_description: 'The client_assertion typ should be set',
        })
      }

      if (clientAssertionClaims['sub'] !== client_id) {
        console.error(
          'Incorrect sub in client_assertion claims. Found',
          clientAssertionClaims['sub'],
          'but should be',
          client_id,
        )
        return res.status(401).send({
          error: 'invalid_client',
          error_description: 'Incorrect sub in client_assertion claims',
        })
      }

      // According to OIDC spec, asp must check the aud claim.
      const iss = `${req.protocol}://${req.get('host')}/singpass/v3`

      if (clientAssertionClaims['aud'] !== iss) {
        console.error(
          'Incorrect aud in client_assertion claims. Found',
          clientAssertionClaims['aud'],
          'but should be',
          iss,
        )
        return res.status(401).send({
          error: 'invalid_client',
          error_description: 'Incorrect aud in client_assertion claims',
        })
      }

      // Step 1: Obtain profile for which the auth code requested data for
      const { profile, nonce, scopes } = lookUpByAuthCode(authCode, {
        isStateless,
      })

      // Step 2: Get ID token
      const aud = clientAssertionClaims['sub']
      console.debug('Received token request', {
        code: authCode,
        client_id: aud,
        redirect_uri: redirectURI,
      })

      const useAuthCode =
        scopes.split(' ').filter((s) => s !== 'openid').length > 0

      const { idTokenClaims, accessToken } = assertions.oidc.create.singPass(
        profile,
        iss,
        aud,
        nonce,
        useAuthCode ? authCode : undefined,
      )

      // Step 3: Sign ID token with ASP signing key
      const aspKeyset = JSON.parse(aspSecret)
      const aspSigningKey = aspKeyset.keys.find(
        (item) =>
          item.use === 'sig' && item.kty === 'EC' && item.crv === 'P-256',
      )
      if (!aspSigningKey) {
        console.error('No suitable signing key found', aspKeyset.keys)
        return res.status(400).send({
          error: 'invalid_request',
          error_description: 'No suitable signing key found',
        })
      }
      const signingKey = await jose.importJWK(aspSigningKey, 'ES256')
      const signedProtectedHeader = {
        alg: 'ES256',
        typ: 'JWT',
        kid: aspSigningKey.kid,
      }
      const signedIdToken = await new jose.CompactSign(
        new TextEncoder().encode(JSON.stringify(idTokenClaims)),
      )
        .setProtectedHeader(signedProtectedHeader)
        .sign(signingKey)

      // Step 4: Encrypt ID token with RP encryption key
      if (!rpEncryptionKey) {
        console.error('No suitable encryption key found', rpKeysetJson.keys)
        return res.status(400).send({
          error: 'invalid_request',
          error_description: 'No suitable encryption key found',
        })
      }
      console.debug('Using encryption key', rpEncryptionKey)
      const encryptedProtectedHeader = {
        alg: rpEncryptionKey.alg,
        typ: 'JWT',
        kid: rpEncryptionKey.kid,
        enc: 'A256CBC-HS512',
        cty: 'JWT',
      }
      const idToken = await new jose.CompactEncrypt(
        new TextEncoder().encode(signedIdToken),
      )
        .setProtectedHeader(encryptedProtectedHeader)
        .encrypt(await jose.importJWK(rpEncryptionKey, rpEncryptionKey.alg))

      console.debug('ID Token', idToken)
      // Step 5: Send token
      res.status(200).send({
        access_token: accessToken,
        token_type: 'Bearer',
        id_token: idToken,
      })
    },
  )

  app.get(`/singpass/v3/.well-known/openid-configuration`, (req, res) => {
    const baseUrl = `${req.protocol}://${req.get('host')}/singpass/v3`

    // Note: does not support backchannel auth
    const data = {
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/auth`,
      jwks_uri: `${baseUrl}/.well-known/keys`,
      response_types_supported: ['code'],
      scopes_supported: singpass_allowed_scopes,
      subject_types_supported: ['public'],
      claims_supported: ['nonce', 'aud', 'iss', 'sub', 'exp', 'iat'],
      grant_types_supported: ['authorization_code'],
      token_endpoint: `${baseUrl}/token`,
      token_endpoint_auth_methods_supported: ['private_key_jwt'],
      token_endpoint_auth_signing_alg_values_supported:
        token_endpoint_auth_signing_alg_values_supported.singPass,
      id_token_signing_alg_values_supported: ['ES256'],
      id_token_encryption_alg_values_supported:
        id_token_encryption_alg_values_supported.singPass,
      id_token_encryption_enc_values_supported: ['A256CBC-HS512'],
      userinfo_endpoint: `${baseUrl}/userinfo`,
      userinfo_signing_alg_values_supported: ['ES256'],
      userinfo_encryption_alg_values_supported: [
        'ECDH-ES+A256KW',
        'ECDH-ES+A192KW',
        'ECDH-ES+A128KW',
      ],
      userinfo_encryption_enc_values_supported: ['A256GCM'],
    }

    res.status(200).send(data)
  })

  app.get(`/singpass/v3/.well-known/keys`, (req, res) => {
    res.status(200).send(JSON.parse(aspPublic))
  })

  app.get(`/singpass/v3/userinfo`, async (req, res) => {
    const authCode = (
      req.headers.authorization || req.headers.Authorization
    ).replace('Bearer ', '')

    const { profile, scopes } = lookUpByAuthCode(authCode, {
      isStateless,
    })
    const customProfile = profile.customProfile
    const uuid = profile.uuid
    const nric = customProfile
      ? profile.nric
      : assertions.oidc.singPass.find((p) => p.uuid === uuid)?.nric
    const persona = customProfile
      ? buildRandomProfile(profile.uuid, profile.nric)
      : assertions.myinfo.v3.personas[nric]

    let rpEncryptionKey
    try {
      const { encryptionKey } = await getRelayPartyKeySets()
      rpEncryptionKey = encryptionKey
    } catch (e) {
      return res.status(e.code).send({
        error: e.error,
        error_description: e.message,
      })
    }

    if (!rpEncryptionKey) {
      console.error('No suitable encryption key found')
      return res.status(400).send({
        error: 'invalid_request',
        error_description: 'No suitable encryption key found',
      })
    }
    const encryptedProtectedHeader = {
      alg: rpEncryptionKey.alg,
      kid: rpEncryptionKey.kid,
      enc: 'A256GCM',
      typ: 'JWT',
      cty: 'JWT',
    }

    const scopesArr = scopes.split(' ').filter((field) => field !== 'openid')
    const myInfoFields = await Promise.all(
      scopesArr.map((scope) => persona[scope]),
    )

    const data = {}
    scopesArr.forEach((name, index) => {
      data[name] = myInfoFields[index]
    })

    const aspKeyset = JSON.parse(aspSecret)
    const aspSigningKey = aspKeyset.keys.find(
      (item) => item.use === 'sig' && item.kty === 'EC' && item.crv === 'P-256',
    )
    if (!aspSigningKey) {
      console.error('No suitable signing key found', aspKeyset.keys)
      return res.status(400).send({
        error: 'invalid_request',
        error_description: 'No suitable signing key found',
      })
    }

    const signingKey = await jose.importJWK(aspSigningKey, 'ES256')
    const encryptedJwt = await new jose.SignJWT(data)
      .setProtectedHeader({
        alg: 'ES256',
      })
      .sign(signingKey)

    const jweToken = await new jose.CompactEncrypt(Buffer.from(encryptedJwt))
      .setProtectedHeader(encryptedProtectedHeader)
      .encrypt(await jose.importJWK(rpEncryptionKey, rpEncryptionKey.alg))

    res.json(jweToken)
  })

  return app
}

function buildRandomProfile(uuid, nric) {
  const infoTemplate = myinfo.template
  const fakeName = faker.person.fullName().toUpperCase()
  return {
    ...infoTemplate,
    uuid: {
      source: '1',
      classification: 'C',
      value: uuid,
    },
    name: {
      lastupdated: '2020-04-16',
      source: '1',
      classification: 'C',
      value: fakeName,
    },
    uinfin: {
      lastupdated: '2020-04-16',
      source: '1',
      classification: 'C',
      value: nric,
    },
    partialuinfin: {
      lastupdated: '2020-04-16',
      source: '1',
      classification: 'C',
      value: `*****${nric.slice(-4)}`,
    },
  }
}

module.exports = config
