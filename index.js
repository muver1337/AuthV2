const app = require('./app')
const port = process.env.PORT || 5000
const DB_URL = "mongodb+srv://admin:admin@cluster0.olkojnl.mongodb.net/?retryWrites=true&w=majority";

app.listen(port, () => console.log(`Server has been started port: ${port}`))