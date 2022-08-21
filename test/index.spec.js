const {expect} = require('chai')

const axios = require('axios').default

const port = '6000'
const baseUrl = `http://localhost:${port}`

function callHealth() {
    return axios.get(`${baseUrl}/health`)
}

describe('OAuth2 Auth Server', () => {

    let server

    before(() => {
        if (!server) {
            try {
                process.env.PORT = port
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
})
