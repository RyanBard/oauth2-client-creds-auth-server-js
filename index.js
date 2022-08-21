const port = process.env.PORT || '3000'

const express = require('express')

function log(fmt, ...params) {
    console.log(fmt, ...params)
}

const app = express()

app.use(express.json())

app.get('/health', (req, res) => res.json({status: 'UP'}))

const server = app.listen(port, () => log('Listening on port', port))

module.exports = {
    close: function (...args) {
        server.close(...args)
    }
}
