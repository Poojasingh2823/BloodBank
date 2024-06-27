const express = require('express')
const colors = require('colors')
const morgan = require('morgan')
const cors = require('cors')
const dotenv = require('dotenv')
const connectDB = require('./config/db')
const path = require('path')

// env config
dotenv.config()

// mongodb connection
connectDB();

const app = express()

app.use(cors())
app.use(morgan('dev'))

app.use(express.json())


app.use("/api/v1/test", require("./routes/testRoutes"));
app.use("/api/v1/auth", require("./routes/authRoutes"));
app.use("/api/v1/inventory", require("./routes/inventoryRoutes"));
app.use("/api/v1/analytics", require("./routes/analyticsRoutes"));
app.use("/api/v1/admin", require("./routes/adminRoutes"));

//Static Folder
app.use(express.static(path.join(__dirname,'./client/build')))

//Static Routes
app.get('*',function(req,res){
    res.sendFile(path.join(__dirname,'./client/build/index.html'))
})

const PORT=process.env.PORT || 8000;

app.listen(PORT,()=>{
    console.log(`Node Server Running in ${process.env.DEV_MODE} mode on port ${process.env.PORT}`.bgBlue.white)
})