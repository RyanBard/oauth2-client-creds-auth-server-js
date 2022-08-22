const {expect} = require('chai')
const qs = require('querystring')
const jwt = require('jsonwebtoken')

const axios = require('axios').default

const port = '6000'
const baseUrl = `http://localhost:${port}`

function callHealth() {
    return axios.get(`${baseUrl}/health`)
}

function callToken({auth = '', clientId, clientSecret, grantType}) {
    const body = {
        grant_type: grantType,
    }
    const options = {
        method: 'post',
        baseURL: baseUrl,
        url: '/token',
    }
    if (['body', 'both'].includes(auth)) {
        body.client_id = clientId
        body.client_secret = clientSecret
    }
    if (['', 'header', 'both'].includes(auth)) {
        options.auth = {
            username: clientId,
            password: clientSecret,
        }
    }
    options.data = qs.stringify(body)
    return axios(options)
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
            expect(resp.data).to.eql({status: 'UP'})
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
            expect(resp.data.token_type).to.eql('Bearer')
            expect(resp.data.access_token).to.not.be.undefined
            expect(resp.data.refresh_token).to.be.undefined
            expect(resp.data.expires_in).to.eql(expiresIn)
        })

        it('should be successful when client id + secret are in the auth header', async () => {
            const resp = await callToken({clientId, clientSecret, grantType})
            expect(resp.status).to.eql(200)
            expect(resp.data.token_type).to.eql('Bearer')
            expect(resp.data.access_token).to.not.be.undefined
            expect(resp.data.refresh_token).to.be.undefined
            expect(resp.data.expires_in).to.eql(expiresIn)
        })

        it('should 401 with an error of invalid_client when missing client_id', async () => {
            try {
                await callToken({clientId: '', clientSecret, grantType})
                expect.fail('Unexpected success!')
            } catch (err) {
                const resp = err.response
                if (!resp) {
                    throw err
                }
                expect(resp.status).to.eql(401)
                expect(resp.data.error).to.eql('invalid_client')
                expect(resp.data.error_description).contains('client_id')
            }
        })

        it('should 401 with an error of invalid_client when missing client_secret', async () => {
            try {
                await callToken({clientId, clientSecret: '', grantType})
                expect.fail('Unexpected success!')
            } catch (err) {
                const resp = err.response
                if (!resp) {
                    throw err
                }
                expect(resp.status).to.eql(401)
                expect(resp.data.error).to.eql('invalid_client')
                expect(resp.data.error_description).contains('client_secret')
            }
        })

        it('should 400 with an error of invalid_grant when missing grant_type', async () => {
            try {
                await callToken({clientId, clientSecret, grantType: ''})
                expect.fail('Unexpected success!')
            } catch (err) {
                const resp = err.response
                if (!resp) {
                    throw err
                }
                expect(resp.status).to.eql(400)
                expect(resp.data.error).to.eql('invalid_grant')
                expect(resp.data.error_description).contains('grant_type')
            }
        })

        it('should 400 with an error of unsupported_grant_type when not client_credentials grant_type', async () => {
            try {
                await callToken({clientId, clientSecret, grantType: 'password'})
                expect.fail('Unexpected success!')
            } catch (err) {
                const resp = err.response
                if (!resp) {
                    throw err
                }
                expect(resp.status).to.eql(400)
                expect(resp.data.error).to.eql('unsupported_grant_type')
                expect(resp.data.error_description).contains('grant_type')
            }
        })

        it('should 400 with an error of invalid_request when client creds are specified in both header and body', async () => {
            try {
                await callToken({auth: 'both', clientId, clientSecret, grantType})
                expect.fail('Unexpected success!')
            } catch (err) {
                const resp = err.response
                if (!resp) {
                    throw err
                }
                expect(resp.status).to.eql(400)
                expect(resp.data.error).to.eql('invalid_request')
            }
        })
    })

    describe('Foo API', () => {
        it('should 200 when auth token is valid', async () => {
            const tokenResp = await callToken({clientId, clientSecret, grantType})
            const validJwt  = tokenResp.data.access_token
            const resp = await axios.get(`${baseUrl}/api/foo`, {headers: {Authorization: `Bearer ${validJwt}`}})
            expect(resp.status).to.eql(200)
            expect(resp.data.message).to.eql('success!')
        })

        it('should 401 when no auth is provided', async () => {
            try {
                await axios.get(`${baseUrl}/api/foo`)
                expect.fail('Unexpected success!')
            } catch (err) {
                const resp = err.response
                if (!resp) {
                    throw err
                }
                expect(resp.status).to.eql(401)
            }
        })

        it('should 401 when auth token is malformed', async () => {
            const invalidJwt = 'todo'
            try {
                await axios.get(`${baseUrl}/api/foo`, {headers: {Authorization: `Bearer ${invalidJwt}`}})
                expect.fail('Unexpected success!')
            } catch (err) {
                const resp = err.response
                if (!resp) {
                    throw err
                }
                expect(resp.status).to.eql(401)
            }
        })

        it('should 401 when auth token is well formed, but invalid', async () => {
            const invalidJwt = await signJwt()
            try {
                await axios.get(`${baseUrl}/api/foo`, {headers: {Authorization: `Bearer ${invalidJwt}`}})
                expect.fail('Unexpected success!')
            } catch (err) {
                const resp = err.response
                if (!resp) {
                    throw err
                }
                expect(resp.status).to.eql(401)
            }
        })
    })
})
