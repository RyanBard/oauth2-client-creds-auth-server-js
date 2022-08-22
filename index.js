function mustHaveEnvVar(name) {
    const val = process.env[name]
    if (!val) {
        throw new Error(`Must specify ${name}!`)
    }
    return val
}

const port = process.env.PORT || '3000'
const cfgClientId = mustHaveEnvVar('CLIENT_ID')
const cfgClientSecret = mustHaveEnvVar('CLIENT_SECRET')
const cfgExpiresIn = parseInt(process.env.EXPIRES_IN || '300', 10)
const cfgJwtSecret = mustHaveEnvVar('JWT_SECRET')

const jwt = require('jsonwebtoken');
const express = require('express')
const {
    createLogger,
    format,
    transports,
} = require('winston')
const uuid = require('uuid').v4

const log = createLogger({
    level: process.env.LOG_LEVEL || 'debug',
    format: format.json(),
})

if (process.env.NODE_ENV !== 'production') {
    log.add(new transports.Console({
        format: format.combine(
            format.colorize(),
            format.timestamp(),
            format.splat(),
            format.printf(({level, message, timestamp}) =>
                `${timestamp} ${level}: ${message}`
            ),
        )
    }))
}

function generateAccessToken() {
    return signJwt()
}

function signJwt() {
    const options = {
        algorithm: 'HS256',
        expiresIn: cfgExpiresIn + ' seconds',
        audience: 'example-auth-server',
        issuer: 'example-auth-server',
        subject: cfgClientId,
    }
    const customClaims = {
        nonce: uuid(),
    }
    return new Promise((resolve, reject) => {
        jwt.sign(customClaims, cfgJwtSecret, options, (err, token) => {
            if (err) {
                return reject(err)
            }
            return resolve(token)
        })
    })
}

function validateJwt(token) {
    const options = {
        algorithms: ['HS256'],
        clockTolerance: 60,
        clockTimestamp: Math.floor(Date.now() / 1000),
    }
    return jwt.verify(token, cfgJwtSecret, options)
}

const app = express()

app.use(express.json())
app.use(express.urlencoded({extended: true}))

app.get('/health', (req, res) => res.json({status: 'UP'}))

app.use('/token', (req, res, next) => {
    const authorization = req.headers.authorization || '';
    const b64UserPass = authorization.replace(/^Basic /, '').trim();
    const [username, password] = Buffer.from(b64UserPass, 'base64').toString('utf8').split(':');
    res.locals.clientId = username;
    res.locals.clientSecret = password;
    return next();
})

app.post('/token', async (req, res) => {
    log.debug('token called')
    const clientId = res.locals.clientId || req.body.client_id
    const clientSecret = res.locals.clientSecret || req.body.client_secret

    if (!clientId || !clientSecret || clientId !== cfgClientId || clientSecret !== cfgClientSecret) {
        log.debug('invalid credentials')
        return res.status(401).json({
            error: 'invalid_client',
            error_description: 'Invalid client_id / client_secret',
        })
    }

    const headerAuthUsed = res.locals.clientId || res.locals.clientSecret
    const bodyAuthUsed = req.body.client_id || req.body.client_secret
    if (headerAuthUsed && bodyAuthUsed) {
        log.warn('client creds specified in header and body')
        return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Must specify client id + secret in only 1 place'
        })
    }

    if (!req.body.grant_type) {
        log.warn('missing grant type')
        return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'Must specify grant_type',
        })
    }

    if (req.body.grant_type !== 'client_credentials') {
        log.warn('wrong grant type')
        return res.status(400).json({
            error: 'unsupported_grant_type',
            error_description: 'Only client_credentials grant_type is supported',
        })
    }

    log.debug('everything was valid, trying to return an access token response')
    try {
        return res.header('Cache-Control', 'no-store').json({
            access_token: await generateAccessToken(),
            expires_in: cfgExpiresIn,
            token_type: 'Bearer',
        })
    } catch (err) {
        log.error('something went wrong: %O', {message: err.message, stack: err.stack})
        return res.sendStatus(500)
    }
})

app.use('/api/*', (req, res, next) => {
    const authorization = req.headers.authorization || '';
    const authToken = authorization.replace(/^Bearer /, '').trim();
    if (!authToken) {
        return res.sendStatus(401)
    }
    try {
        res.locals.decodedJwt = validateJwt(authToken)
    } catch (err) {
        log.debug('Invalid jwt: %O', {message: err.message, stack: err.stack})
        return res.sendStatus(401)
    }
    return next();
})

app.get('/api/foo', (req, res) => res.json({message: 'success!'}))

const server = app.listen(port, () => log.info('Listening on port', port))

module.exports = {
    close: function (...args) {
        server.close(...args)
    }
}
