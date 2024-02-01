module.exports = {
    mongoURL: "mongodb+srv://admin:admin@cluster0.pr8jsge.mongodb.net/?retryWrites=true&w=majority",
    jwt: {
        secret: 'dev-jwt',
        tokens: {
            access: {
                type: 'access',
                expiresIn: '5m',
            },
            refresh: {
                type: 'refresh',
                expiresIn: '6m',
            },
        },
    },
};
