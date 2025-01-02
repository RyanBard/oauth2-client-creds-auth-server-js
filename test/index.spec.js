const {expect} = require('chai')
const qs = require('querystring')
const jwt = require('jsonwebtoken')

const port = '5000'
const baseUrl = `http://localhost:${port}`

function callHealth() {
    return fetch(`${baseUrl}/health`)
}

function callToken({auth = '', clientId, clientSecret, grantType}) {
    const body = new URLSearchParams()
    body.set('grant_type', grantType)

    if (['body', 'both'].includes(auth)) {
        body.set('client_id', clientId)
        body.set('client_secret', clientSecret)
    }

    const options = {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
    }

    if (['', 'header', 'both'].includes(auth)) {
        options.headers.Authorization = 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`, 'ascii').toString('base64')
    }

    return fetch(`${baseUrl}/token`, options)
}

function signJwt() {
    const options = {
        algorithm: 'HS256',
        expiresIn: '300 seconds',
        audience: 'example-auth-server',
        issuer: 'example-auth-server',
        subject: 'whatever',
    }
    const customClaims = {}
    return new Promise((resolve, reject) => {
        jwt.sign(customClaims, 'invalid-client-secret', options, (err, token) => {
            if (err) {
                return reject(err)
            }
            return resolve(token)
        })
    })
}


describe('OAuth2 Auth Server', () => {

    let server
    let clientId = 'test-client-id'
    let clientSecret = 'test-client-secret'
    let grantType = 'client_credentials'
    let expiresIn = 60

    before(() => {
        if (!server) {
            try {
                process.env.PORT = port
                process.env.LOG_LEVEL = 'error'
                process.env.CLIENT_ID = clientId
                process.env.CLIENT_SECRET = clientSecret
                process.env.EXPIRES_IN = '' + expiresIn
                process.env.JWT_SECRET = 'foobar'
                delete require.cache[require.resolve('../index')]
                server = require('../index')
            } catch (e) {
                log('Error: %O', {message: e.message, stack: e.stack})
                expect.fail('Something went wrong!')
            }
        }
    })

    after((done) => {
        if (server) {
            server.close(done)
        } else {
            done()
        }
    })

    describe('Health Check', () => {
        it('should be successful', async () => {
            const resp = await callHealth()
            expect(resp.status).to.eql(200)
            const data = await resp.json()
            expect(data).to.eql({status: 'UP'})
        })
    })

    /*
     * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4
     * https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1
     * https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
     */
    describe('Token', () => {
        it('should be successful when client id + secret are in the body', async () => {
            const resp = await callToken({auth: 'body', clientId, clientSecret, grantType})
            expect(resp.status).to.eql(200)
            const data = await resp.json()
            expect(data.token_type).to.eql('Bearer')
            expect(data.access_token).to.not.be.undefined
            expect(data.refresh_token).to.be.undefined
            expect(data.expires_in).to.eql(expiresIn)
        })

        it('should be successful when client id + secret are in the auth header', async () => {
            const resp = await callToken({clientId, clientSecret, grantType})
            expect(resp.status).to.eql(200)
            const data = await resp.json()
            expect(data.token_type).to.eql('Bearer')
            expect(data.access_token).to.not.be.undefined
            expect(data.refresh_token).to.be.undefined
            expect(data.expires_in).to.eql(expiresIn)
        })

        it('should 401 with an error of invalid_client when missing client_id', async () => {
            const resp = await callToken({clientId: '', clientSecret, grantType})
            expect(resp.status).to.eql(401)
            const data = await resp.json()
            expect(data.error).to.eql('invalid_client')
            expect(data.error_description).contains('client_id')
        })

        it('should 401 with an error of invalid_client when missing client_secret', async () => {
            const resp = await callToken({clientId, clientSecret: '', grantType})
            expect(resp.status).to.eql(401)
            const data = await resp.json()
            expect(data.error).to.eql('invalid_client')
            expect(data.error_description).contains('client_secret')
        })

        it('should 400 with an error of invalid_grant when missing grant_type', async () => {
            const resp = await callToken({clientId, clientSecret, grantType: ''})
            expect(resp.status).to.eql(400)
            const data = await resp.json()
            expect(data.error).to.eql('invalid_grant')
            expect(data.error_description).contains('grant_type')
        })

        it('should 400 with an error of unsupported_grant_type when not client_credentials grant_type', async () => {
            const resp = await callToken({clientId, clientSecret, grantType: 'password'})
            expect(resp.status).to.eql(400)
            const data = await resp.json()
            expect(data.error).to.eql('unsupported_grant_type')
            expect(data.error_description).contains('grant_type')
        })

        it('should 400 with an error of invalid_request when client creds are specified in both header and body', async () => {
            const resp = await callToken({auth: 'both', clientId, clientSecret, grantType})
            expect(resp.status).to.eql(400)
            const data = await resp.json()
            expect(data.error).to.eql('invalid_request')
        })
    })

    describe('Foo API', () => {
        it('should 200 when auth token is valid', async () => {
            const tokenResp = await callToken({clientId, clientSecret, grantType})
            const validJwt  = (await tokenResp.json()).access_token
            const resp = await fetch(`${baseUrl}/api/foo`, {headers: {Authorization: `Bearer ${validJwt}`}})
            expect(resp.status).to.eql(200)
            const data = await resp.json()
            expect(data.message).to.eql('success!')
        })

        it('should 401 when no auth is provided', async () => {
            const resp = await fetch(`${baseUrl}/api/foo`)
            expect(resp.status).to.eql(401)
        })

        it('should 401 when auth token is malformed', async () => {
            const invalidJwt = 'todo'
            const resp = await fetch(`${baseUrl}/api/foo`, {headers: {Authorization: `Bearer ${invalidJwt}`}})
            expect(resp.status).to.eql(401)
        })

        it('should 401 when auth token is well formed, but invalid', async () => {
            const invalidJwt = await signJwt()
            const resp = await fetch(`${baseUrl}/api/foo`, {headers: {Authorization: `Bearer ${invalidJwt}`}})
            expect(resp.status).to.eql(401)
        })
    })
})
